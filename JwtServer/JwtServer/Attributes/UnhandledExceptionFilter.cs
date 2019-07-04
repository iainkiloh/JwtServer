﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using JwtServer.Infrastructure;
using System;
using System.Security.Authentication;

namespace JwtServerAttributes
{
    public class UnhandledExceptionFilter : ExceptionFilterAttribute
    {

        public override void OnException(ExceptionContext context)
        {

            if (context.Exception is UnauthorizedAccessException)
            {
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.Unauthorized;
                context.Result = new StatusCodeResult(StatusCodes.Status401Unauthorized);
            }
            else if (context.Exception is ArgumentNullException) 
            {
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.BadRequest;
                context.Result = new StatusCodeResult(StatusCodes.Status400BadRequest);
            }
            else if (context.Exception is InvalidCredentialException)
            {
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.Forbidden;
                context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
            }
            if (context.Exception is OperationCanceledException)
            {
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.BadRequest;
                context.Result = new StatusCodeResult(StatusCodes.Status400BadRequest);
            }
            else
            {
                //log the exception
                var port = context.HttpContext.Request.Host.Port;
                var host = context.HttpContext.Request.Host.Value;
                var controllerDescriptor = context.ActionDescriptor as ControllerActionDescriptor;
                var controllerFullName = controllerDescriptor.ControllerTypeInfo.FullName;
                var actionName = controllerDescriptor.ActionName;

                //TODO - add your api name below

                    Logging.logger.Log(
                      NLog.LogLevel.Error,
                      Environment.NewLine +
                      "APIName: " + "JwtServer" + ", Host:" + host + ", Port:" + port + ", Controller: " + controllerFullName + ", ActionName: " + actionName + ", Exception: " + context.Exception.Message + ", DateTime: " + DateTime.Now.ToString()
                       + Environment.NewLine);

              
                context.HttpContext.Response.StatusCode = (int)System.Net.HttpStatusCode.InternalServerError;
            }
        }

    }

}
