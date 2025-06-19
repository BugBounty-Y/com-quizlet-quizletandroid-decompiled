package com.google.gson;

import java.lang.reflect.Field;

/* loaded from: classes2.dex */
public enum a extends g {
    public a() {
        super("IDENTITY", 0);
    }

    @Override // com.google.gson.g
    public final String b(Field field) {
        return field.getName();
    }
}
