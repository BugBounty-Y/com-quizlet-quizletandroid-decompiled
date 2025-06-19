package com.google.gson;

import java.lang.reflect.Field;
import java.util.Locale;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public abstract class g {
    public static final a a;
    public static final /* synthetic */ g[] b;

    static {
        a aVar = new a();
        a = aVar;
        b = new g[]{aVar, new g() { // from class: com.google.gson.b
            @Override // com.google.gson.g
            public final String b(Field field) {
                return g.c(field.getName());
            }
        }, new g() { // from class: com.google.gson.c
            @Override // com.google.gson.g
            public final String b(Field field) {
                return g.c(g.a(field.getName(), " "));
            }
        }, new g() { // from class: com.google.gson.d
            @Override // com.google.gson.g
            public final String b(Field field) {
                return g.a(field.getName(), "_").toLowerCase(Locale.ENGLISH);
            }
        }, new g() { // from class: com.google.gson.e
            @Override // com.google.gson.g
            public final String b(Field field) {
                return g.a(field.getName(), "-").toLowerCase(Locale.ENGLISH);
            }
        }, new g() { // from class: com.google.gson.f
            @Override // com.google.gson.g
            public final String b(Field field) {
                return g.a(field.getName(), ".").toLowerCase(Locale.ENGLISH);
            }
        }};
    }

    public static String a(String str, String str2) {
        StringBuilder sb = new StringBuilder();
        int length = str.length();
        for (int i = 0; i < length; i++) {
            char cCharAt = str.charAt(i);
            if (Character.isUpperCase(cCharAt) && sb.length() != 0) {
                sb.append(str2);
            }
            sb.append(cCharAt);
        }
        return sb.toString();
    }

    public static String c(String str) {
        int length = str.length() - 1;
        int i = 0;
        while (!Character.isLetter(str.charAt(i)) && i < length) {
            i++;
        }
        char cCharAt = str.charAt(i);
        if (Character.isUpperCase(cCharAt)) {
            return str;
        }
        char upperCase = Character.toUpperCase(cCharAt);
        if (i == 0) {
            return upperCase + str.substring(1);
        }
        return str.substring(0, i) + upperCase + str.substring(i + 1);
    }

    public static g valueOf(String str) {
        return (g) Enum.valueOf(g.class, str);
    }

    public static g[] values() {
        return (g[]) b.clone();
    }

    public abstract String b(Field field);
}
