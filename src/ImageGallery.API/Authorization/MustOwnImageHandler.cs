﻿using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Filters;
using ImageGallery.API.Services;

namespace ImageGallery.API.Authorization
{
    public class MustOwnImageHandler : AuthorizationHandler<MustOwnImageRequirement>
    {
        private readonly IGalleryRepository _galleryRepository;

        public MustOwnImageHandler(IGalleryRepository galleryRepository)
        {
            _galleryRepository = galleryRepository;
        }

        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, MustOwnImageRequirement requirement)
        {
            var filterContext = context.Resource as AuthorizationFilterContext;
            if (filterContext == null)
            {
                context.Fail();
                return Task.FromResult(0);
            }

            var imageId = filterContext.RouteData.Values["id"].ToString();

            // try to parse it to a Guid
            Guid imageIdAsGuid;
            if (!Guid.TryParse(imageId, out imageIdAsGuid))
            {
                context.Fail();
                return Task.FromResult(0);
            }

            // get the sub claim
            var ownerId = context.User.Claims.FirstOrDefault(c => c.Type == "sub").Value;

            if (!_galleryRepository.IsImageOwner(imageIdAsGuid, ownerId))
            {
                context.Fail();
                return Task.FromResult(0);
            }

            context.Succeed(requirement);
            return Task.FromResult(0);
        }
    }
}
