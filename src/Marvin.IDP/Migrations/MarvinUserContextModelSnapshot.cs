﻿using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Marvin.IDP.Entities;

namespace Marvin.IDP.Migrations
{
    [DbContext(typeof(MarvinUserContext))]
    partial class MarvinUserContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
            modelBuilder
                .HasAnnotation("ProductVersion", "1.1.2")
                .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

            modelBuilder.Entity("Marvin.IDP.Entities.User", b =>
                {
                    b.Property<string>("SubjectId")
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(50);

                    b.Property<bool>("IsActive");

                    b.Property<string>("Password")
                        .HasMaxLength(100);

                    b.Property<string>("Username")
                        .IsRequired()
                        .HasMaxLength(100);

                    b.HasKey("SubjectId");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("Marvin.IDP.Entities.UserClaim", b =>
                {
                    b.Property<string>("Id")
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(50);

                    b.Property<string>("ClaimType")
                        .IsRequired()
                        .HasMaxLength(250);

                    b.Property<string>("ClaimValue")
                        .IsRequired()
                        .HasMaxLength(250);

                    b.Property<string>("SubjectId")
                        .IsRequired()
                        .HasMaxLength(50);

                    b.HasKey("Id");

                    b.HasIndex("SubjectId");

                    b.ToTable("Claims");
                });

            modelBuilder.Entity("Marvin.IDP.Entities.UserLogin", b =>
                {
                    b.Property<string>("Id")
                        .ValueGeneratedOnAdd()
                        .HasMaxLength(50);

                    b.Property<string>("LoginProvider")
                        .IsRequired()
                        .HasMaxLength(250);

                    b.Property<string>("ProviderKey")
                        .IsRequired()
                        .HasMaxLength(250);

                    b.Property<string>("SubjectId")
                        .IsRequired()
                        .HasMaxLength(50);

                    b.HasKey("Id");

                    b.HasIndex("SubjectId");

                    b.ToTable("UserLogins");
                });

            modelBuilder.Entity("Marvin.IDP.Entities.UserClaim", b =>
                {
                    b.HasOne("Marvin.IDP.Entities.User")
                        .WithMany("Claims")
                        .HasForeignKey("SubjectId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("Marvin.IDP.Entities.UserLogin", b =>
                {
                    b.HasOne("Marvin.IDP.Entities.User")
                        .WithMany("Logins")
                        .HasForeignKey("SubjectId")
                        .OnDelete(DeleteBehavior.Cascade);
                });
        }
    }
}
