package com.braze.triggers.events;

/* loaded from: classes.dex */
public final class d extends i {
    public final String e;
    public final String f;

    public d(String str) {
        this.e = i.a(str);
    }

    @Override // com.braze.triggers.events.b
    public final String a() {
        return "iam_click";
    }

    public d(String str, String str2) {
        this.e = i.a(str);
        this.f = str2;
    }
}
