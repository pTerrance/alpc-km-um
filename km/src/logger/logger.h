// MIT License
//
// Copyright (c) 2023 pTerrance
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef ALPCKM_SRC_LOGGER_LOGGER_H_
#define ALPCKM_SRC_LOGGER_LOGGER_H_

#define LOG(type, format, ...) DbgPrint("[>.<] [" type "] " format "\n", ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) LOG("debug", format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) LOG("info", format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) LOG("error", format, ##__VA_ARGS__)
#define LOG_FATAL(format, ...) LOG("fatal", format, ##__VA_ARGS__)

#endif //ALPCKM_SRC_LOGGER_LOGGER_H_
