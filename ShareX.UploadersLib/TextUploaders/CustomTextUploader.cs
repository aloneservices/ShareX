#region License Information (GPL v3)

/*
    ShareX - A program that allows you to take screenshots and share any file type
    Copyright (c) 2007-2025 ShareX Team

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

    Optionally you can also view the license at <http://www.gnu.org/licenses/>.
*/

#endregion License Information (GPL v3)

using ShareX.HelpersLib;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;
using ProtoBuf;
using ShareX.UploadersLib.Encryption;
using ShareX.UploadersLib.Proto;

namespace ShareX.UploadersLib.TextUploaders
{
    public class CustomTextUploaderService : TextUploaderService
    {
        public override TextDestination EnumValue { get; } = TextDestination.CustomTextUploader;

        public override bool CheckConfig(UploadersConfig config)
        {
            return config.CustomUploadersList != null && config.CustomUploadersList.IsValidIndex(config.CustomTextUploaderSelected);
        }

        public override GenericUploader CreateUploader(UploadersConfig config, TaskReferenceHelper taskInfo)
        {
            int index;

            if (taskInfo.OverrideCustomUploader)
            {
                index = taskInfo.CustomUploaderIndex.BetweenOrDefault(0, config.CustomUploadersList.Count - 1);
            }
            else
            {
                index = config.CustomTextUploaderSelected;
            }

            CustomUploaderItem customUploader = config.CustomUploadersList.ReturnIfValidIndex(index);

            if (customUploader != null)
            {
                return new CustomTextUploader(customUploader);
            }

            return null;
        }
    }

    public sealed class CustomTextUploader : TextUploader
    {
        private CustomUploaderItem uploader;

        public CustomTextUploader(CustomUploaderItem customUploaderItem)
        {
            uploader = customUploaderItem;
        }

        public override UploadResult UploadText(string text, string fileName)
        {
            var origStream = new MemoryStream(Encoding.UTF8.GetBytes(text));
            Stream processedStream = origStream;
            var encryptedResult = new AesEncryptedResult();
            if (uploader.Encrypt)
            {
                encryptedResult = AesEncrypter.Encrypt(origStream);
                processedStream = encryptedResult.Stream;
            }

            List<FileChunk> chunks = [];
            byte[] checksum = [];
            if (uploader.Alone)
            {
                processedStream.Seek(0, SeekOrigin.Begin);
                uint order = 0;

                for (var i = 0; i < processedStream.Length; i += UploadersConfig.FileChunkSize)
                {
                    var chunkLen = UploadersConfig.FileChunkSize;
                    if (processedStream.Length - i < chunkLen)
                        chunkLen = (int)(processedStream.Length - i);

                    var data  = new byte[chunkLen];
                    processedStream.ReadExactly(data);

                    chunks.Add(new FileChunk
                    {
                        Order = order,
                        Data = data,
                        Checksum = SHA512.HashData(data)
                    });
                    order++;
                }

                processedStream.Seek(0, SeekOrigin.Begin);
                checksum = SHA512.HashData(processedStream);
            }

            using (var stream = processedStream)
            {
                UploadResult result = new UploadResult();
                CustomUploaderInput input = new CustomUploaderInput(fileName, "", encryptedResult.NonceAndKeyHex);

                if (uploader.Body == CustomUploaderBody.None)
                {
                    result.Response = SendRequest(uploader.RequestMethod, uploader.GetRequestURL(input), null, uploader.GetHeaders(input));
                }
                else if (uploader.Body == CustomUploaderBody.MultipartFormData)
                {
                    if (string.IsNullOrEmpty(uploader.FileFormName))
                    {
                        result.Response = SendRequestMultiPart(uploader.GetRequestURL(input), uploader.GetArguments(input), uploader.GetHeaders(input),
                            null, uploader.RequestMethod);
                    }
                    else
                    {
                        result = SendRequestFile(uploader.GetRequestURL(input), stream, fileName, uploader.GetFileFormName(), uploader.GetArguments(input),
                            uploader.GetHeaders(input), null, uploader.RequestMethod);
                    }
                }
                else if (uploader.Body == CustomUploaderBody.FormURLEncoded)
                {
                    result.Response = SendRequestURLEncoded(uploader.RequestMethod, uploader.GetRequestURL(input), uploader.GetArguments(input), uploader.GetHeaders(input));
                }
                else if (uploader.Body == CustomUploaderBody.JSON || uploader.Body == CustomUploaderBody.XML)
                {
                    result.Response = SendRequest(uploader.RequestMethod, uploader.GetRequestURL(input), uploader.GetData(input), uploader.GetContentType(),
                        null, uploader.GetHeaders(input));
                }
                else if (uploader.Body == CustomUploaderBody.Binary)
                {
                    if (!uploader.Alone)
                    {
                        result.Response = SendRequest(uploader.RequestMethod, uploader.GetRequestURL(input), stream, MimeTypes.GetMimeTypeFromFileName(fileName), null,
                            uploader.GetHeaders(input));
                    }
                    else
                    {
                        var payload = $"{{\"totalChunks\":{chunks.Count},\"checksum\":\"{Convert.ToBase64String(checksum)}\"}}";

                        var encrypted = uploader.Encrypt ? "1" : "";
                        var deleteAfterView = uploader.DeleteAfterView ? "1" : "";
                        var query = $"?encrypted={encrypted}&deleteAfterView={deleteAfterView}";

                        var initialResponse = new UploadResult { Response = SendRequest(uploader.RequestMethod, uploader.GetRequestURL(input) + query, payload, headers: uploader.GetHeaders(input)) };
                        uploader.TryParseResponse(initialResponse, LastResponseInfo, Errors, input);
                        if (!LastResponseInfo.IsSuccess)
                            return initialResponse;

                        var response = JsonConvert.DeserializeObject<Dictionary<string, string>>(initialResponse.Response);
                        var fileId = response.GetValueOrDefault("fileId");

                        foreach (var chunk in chunks)
                        {
                            var memoryStream = new MemoryStream();
                            Serializer.Serialize(memoryStream, chunk);
                            SendRequest(uploader.RequestMethod, $"https://api.alo.ne/file/chunk/{fileId}", memoryStream, headers: uploader.GetHeaders(input));
                        }

                        return initialResponse;
                    }
                }
                else
                {
                    throw new Exception("Unsupported request format: " + uploader.Body);
                }

                uploader.TryParseResponse(result, LastResponseInfo, Errors, input);

                return result;
            }
        }
    }
}