package com.airbnb.lottie.network;

/* loaded from: classes.dex */
public enum b {
    JSON(".json"),
    ZIP(".zip"),
    GZIP(".gz");

    public final String a;

    b(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
