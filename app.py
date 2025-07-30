import json
import logging
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from dataclasses import dataclass
import os
import pandas as pd
from io import BytesIO

from flask import Flask, request, send_file
import requests

# --- Flask App Initialization ---
app = Flask(__name__)


# --- Your Azure Content Understanding Logic (slightly modified) ---

@dataclass(frozen=True, kw_only=True)
class Settings:
    endpoint: str
    api_version: str
    subscription_key: str | None = None
    aad_token: str | None = None
    analyzer_id: str

    def __post_init__(self):
        key_not_provided = (
                not self.subscription_key
                or self.subscription_key == "AZURE_CONTENT_UNDERSTANDING_SUBSCRIPTION_KEY"
        )
        token_not_provided = (
                not self.aad_token
                or self.aad_token == "AZURE_CONTENT_UNDERSTANDING_AAD_TOKEN"
        )
        if key_not_provided and token_not_provided:
            raise ValueError(
                "Either 'subscription_key' or 'aad_token' must be provided"
            )

    @property
    def token_provider(self) -> Callable[[], str] | None:
        aad_token = self.aad_token
        if aad_token is None:
            return None
        return lambda: aad_token


class AzureContentUnderstandingClient:
    def __init__(
            self,
            endpoint: str,
            api_version: str,
            subscription_key: str | None = None,
            token_provider: Callable[[], str] | None = None,
            x_ms_useragent: str = "cu-sample-code",
    ) -> None:
        if not subscription_key and token_provider is None:
            raise ValueError(
                "Either subscription key or token provider must be provided"
            )
        if not api_version:
            raise ValueError("API version must be provided")
        if not endpoint:
            raise ValueError("Endpoint must be provided")

        self._endpoint: str = endpoint.rstrip("/")
        self._api_version: str = api_version
        self._logger: logging.Logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.INFO)
        self._headers: dict[str, str] = self._get_headers(
            subscription_key, token_provider and token_provider(), x_ms_useragent
        )

    def begin_analyze_from_data(self, analyzer_id: str, file_data: bytes):
        """
        Begins the analysis of file data using the specified analyzer.
        """
        headers = {"Content-Type": "application/octet-stream"}
        headers.update(self._headers)

        response = requests.post(
            url=self._get_analyze_url(
                self._endpoint, self._api_version, analyzer_id
            ),
            headers=headers,
            data=file_data,
        )

        response.raise_for_status()
        self._logger.info(
            f"Analyzing uploaded file with analyzer: {analyzer_id}"
        )
        return response

    def poll_result(
            self,
            response: requests.Response,
            timeout_seconds: int = 120,
            polling_interval_seconds: int = 2,
    ) -> dict[str, Any]:
        operation_location = response.headers.get("operation-location", "")
        if not operation_location:
            raise ValueError("Operation location not found in response headers.")

        headers = {"Content-Type": "application/json"}
        headers.update(self._headers)

        start_time = time.time()
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout_seconds:
                raise TimeoutError(
                    f"Operation timed out after {timeout_seconds:.2f} seconds."
                )

            response = requests.get(operation_location, headers=self._headers)
            response.raise_for_status()
            result = cast(dict[str, str], response.json())
            status = result.get("status", "").lower()
            if status == "succeeded":
                return response.json()
            elif status == "failed":
                # --- NEW DETAILED LOGGING ---
                error_details = response.json()
                app.logger.error("!!!!!!!! AZURE ANALYSIS FAILED !!!!!!!!")
                app.logger.error(f"Azure Response: {json.dumps(error_details, indent=2)}")
                raise RuntimeError(f"Azure analysis failed: {json.dumps(error_details)}")
                # --- END OF NEW CODE ---

    def _get_analyze_url(self, endpoint: str, api_version: str, analyzer_id: str):
        return f"{endpoint}/contentunderstanding/analyzers/{analyzer_id}:analyze?api-version={api_version}&stringEncoding=utf16"

    def _get_headers(
            self, subscription_key: str | None, api_token: str | None, x_ms_useragent: str
    ) -> dict[str, str]:
        headers = (
            {"Ocp-Apim-Subscription-Key": subscription_key}
            if subscription_key
            else {"Authorization": f"Bearer {api_token}"}
        )
        headers["x-ms-useragent"] = x_ms_useragent
        return headers


# --- Flask Endpoint ---
@app.route("/analyze", methods=["POST"])
def analyze_invoice():
    """
    This endpoint receives an invoice file, sends it to Azure for analysis,
    and returns the extracted labels and values in an Excel file.
    """
    if 'file' not in request.files:
        return "No file part in the request", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    if file:
        try:
            # --- Get Azure Credentials from Environment Variables ---
            settings = Settings(
                endpoint=os.environ.get("AZURE_ENDPOINT"),
                api_version="2025-05-01-preview",
                subscription_key=os.environ.get("AZURE_SUBSCRIPTION_KEY"),
                analyzer_id=os.environ.get("AZURE_ANALYZER_ID"),
            )

            client = AzureContentUnderstandingClient(
                settings.endpoint,
                settings.api_version,
                subscription_key=settings.subscription_key,
            )

            file_data = file.read()
            response = client.begin_analyze_from_data(settings.analyzer_id, file_data)
            result = client.poll_result(response)

            # --- Process the result to extract key-value pairs ---
            # This part will need to be adjusted based on the actual JSON structure
            # of your Azure AI service's response.
            documents = result.get('analyzeResult', {}).get('documents', [])
            extracted_data = []
            if documents:
                for doc in documents:
                    for name, field in doc.get('fields', {}).items():
                        extracted_data.append({
                            "Label": name,
                            "Value": field.get('content'),
                            "Confidence": field.get('confidence')
                        })

            if not extracted_data:
                return "Could not extract any data from the document.", 500

            # --- Convert to Excel ---
            df = pd.DataFrame(extracted_data)
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, index=False, sheet_name='ExtractedData')

            output.seek(0)

            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name='extracted_invoice_data.xlsx'
            )

        except Exception as e:
            logging.error(f"An error occurred: {e}")
            return str(e), 500

    return "Invalid file", 400


if __name__ == "__main__":
    # For local testing
    app.run(debug=True)


