namespace CrimsonDev.Gameteki.Api.Helpers
{
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Mvc;

    public static class ApiResponseExtensions
    {
        public static ApiResponse FailureResponse(this ControllerBase controller, string message = null)
        {
            return new ApiResponse { Success = false, Message = message };
        }

        public static ApiResponse SuccessResponse(this ControllerBase controller, string message = null)
        {
            return new ApiResponse { Success = true, Message = message };
        }
    }
}
