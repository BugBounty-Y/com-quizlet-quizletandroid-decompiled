package com.arcao.slf4j.timber;

import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public final class b implements org.slf4j.a {
    public static final Pattern b = Pattern.compile("\\$\\d+$");
    public final ConcurrentHashMap a = new ConcurrentHashMap();

    @Override // org.slf4j.a
    public final org.slf4j.b a(String str) {
        Matcher matcher = b.matcher(str);
        if (matcher.find()) {
            str = matcher.replaceAll("");
        }
        String strSubstring = str.substring(str.lastIndexOf(46) + 1);
        ConcurrentHashMap concurrentHashMap = this.a;
        org.slf4j.b bVar = (org.slf4j.b) concurrentHashMap.get(strSubstring);
        if (bVar != null) {
            return bVar;
        }
        a aVar = new a();
        aVar.a = strSubstring;
        org.slf4j.b bVar2 = (org.slf4j.b) concurrentHashMap.putIfAbsent(strSubstring, aVar);
        return bVar2 == null ? aVar : bVar2;
    }
}
