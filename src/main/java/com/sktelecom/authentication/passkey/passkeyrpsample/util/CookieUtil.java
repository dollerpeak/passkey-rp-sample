/*
 * Copyright (C) 2023 SK TELECOM CO., LTD.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sktelecom.authentication.passkey.passkeyrpsample.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class CookieUtil {
    private CookieUtil() {
    }

    public static void addCookie(HttpServletResponse response, String name, String value) {
        Cookie cookie = new Cookie(name, value);
        response.addCookie(cookie);
    }
}
