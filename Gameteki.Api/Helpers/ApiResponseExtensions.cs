namespace CrimsonDev.Gameteki.Api.Helpers
{
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Mvc;

    public static class ApiResponseExtensions
    {
        public static JsonResult FailureResponse(this ControllerBase controller, string message)
        {
            return new JsonResult(new ApiResponse
            {
                Success = false,
                Message = message
            });
        }

        public static JsonResult SuccessResponse(this ControllerBase controller, string message = null)
        {
            return new JsonResult(new ApiResponse { Success = true, Message = message });
        }
    }
}
