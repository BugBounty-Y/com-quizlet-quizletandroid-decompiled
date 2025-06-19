package com.google.android.material.floatingactionbutton;

/* loaded from: classes2.dex */
public final class h {
    public final com.google.firebase.platforminfo.c a;
    public final /* synthetic */ FloatingActionButton b;

    public h(FloatingActionButton floatingActionButton, com.google.firebase.platforminfo.c cVar) {
        this.b = floatingActionButton;
        this.a = cVar;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof h) && ((h) obj).a.equals(this.a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
