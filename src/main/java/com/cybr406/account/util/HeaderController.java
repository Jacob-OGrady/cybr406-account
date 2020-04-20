package com.cybr406.account.util;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

@RestController
public class HeaderController {

    @GetMapping("/headers")
    public String headers(HttpServletRequest request) {
        Enumeration<String> names = request.getHeaderNames();
        List<String> headers = new ArrayList<>();

        while(names.hasMoreElements()) {
            String name = names.nextElement();
            headers.add(name);

            Enumeration<String> values = request.getHeaders(name);
            while(values.hasMoreElements()) {
                String value = values.nextElement();
                headers.add("    " + value);
            }
        }

        return String.join("\n", headers);
    }

}
