<?php
// Step 1: Set the response header to JSON format
header("Content-Type: application/json; charset=UTF-8");

// Step 2: Read the incoming HTTP request method
$method = $_SERVER['REQUEST_METHOD'];

// Helper Tool 1: Extract all incoming HTTP headers (e.g., Authorization)
$headers = function_exists('getallheaders') ? getallheaders() : [];
$authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? 'Not Provided';

// Step 3: Extract raw body input and decode JSON payload
$rawBody = file_get_contents("php://input");
$jsonData = null;

if (!empty($rawBody)) {
    $jsonData = json_decode($rawBody, true);
    
    // Validate JSON syntax to prevent parsing errors
    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400); // 400 Bad Request
        echo json_encode([
            "status" => "error",
            "message" => "Malformed JSON payload: " . json_last_error_msg()
        ], JSON_PRETTY_PRINT);
        exit;
    }
}

// Prepare base response structure
$response = [
    "method_detected" => $method,
    "authorization_header" => $authHeader,
    "timestamp" => date("Y-m-d H:i:s")
];

// Step 4 & 5: Conditional routing based on HTTP method and status code handling
switch ($method) {
    case 'GET':
        http_response_code(200); // 200 OK
        $response["status"] = "success";
        $response["message"] = "GET request processed successfully. Fetching resource data.";
        $response["query_params"] = $_GET;
        break;

    case 'POST':
        if (empty($jsonData)) {
            http_response_code(400); // 400 Bad Request
            $response["status"] = "error";
            $response["message"] = "POST request requires a valid JSON body.";
        } else {
            http_response_code(201); // 201 Created
            $response["status"] = "success";
            $response["message"] = "POST request processed. New resource created.";
            $response["received_data"] = $jsonData;
        }
        break;

    case 'PUT':
        if (empty($jsonData)) {
            http_response_code(400); // 400 Bad Request
            $response["status"] = "error";
            $response["message"] = "PUT request requires a valid JSON body for updating.";
        } else {
            http_response_code(200); // 200 OK
            $response["status"] = "success";
            $response["message"] = "PUT request processed. Existing resource updated.";
            $response["updated_data"] = $jsonData;
        }
        break;

    case 'DELETE':
        http_response_code(200); // 200 OK
        $response["status"] = "success";
        $response["message"] = "DELETE request processed. Target resource removed.";
        $response["deleted_target"] = $jsonData ?? $_GET;
        break;

    default:
        http_response_code(405); // 405 Method Not Allowed
        header("Allow: GET, POST, PUT, DELETE");
        $response["status"] = "error";
        $response["message"] = "HTTP Method '$method' is not allowed on this endpoint.";
        break;
}

// Helper Tool 2: Output formatted JSON response
echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
?>


// 
// curl -i -H "Authorization: Bearer SecretToken123" "http://localhost:8000/api.php?id=10"