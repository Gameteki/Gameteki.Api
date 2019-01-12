namespace CrimsonDev.Gameteki.Api.Helpers
{
    using CrimsonDev.Gameteki.Api.Models.Api.Response;
    using Microsoft.AspNetCore.Mvc;

    public static class ApiResponseExtensions
    {
        public static JsonResult FailureResponse(this Controller controller, string message)
        {
            return new JsonResult(new ApiResponse
            {
                Success = false,
                Message = message
            });
        }

        public static JsonResult SuccessResponse(this Controller controller, string message = null)
        {
            return new JsonResult(new ApiResponse { Success = true, Message = message });
        }
    }
}