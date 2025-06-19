package androidx.navigation;

import android.content.SharedPreferences;

/* renamed from: androidx.navigation.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1288j {
    public boolean a;
    public boolean b;
    public boolean c;
    public Object d;
    public Object e;

    public C1288j(com.google.android.gms.measurement.internal.O o, String str, boolean z) {
        this.e = o;
        com.google.android.gms.common.internal.u.e(str);
        this.d = str;
        this.a = z;
    }

    public void a(boolean z) {
        SharedPreferences.Editor editorEdit = ((com.google.android.gms.measurement.internal.O) this.e).X().edit();
        editorEdit.putBoolean((String) this.d, z);
        editorEdit.apply();
        this.c = z;
    }

    public boolean b() {
        if (!this.b) {
            this.b = true;
            this.c = ((com.google.android.gms.measurement.internal.O) this.e).X().getBoolean((String) this.d, this.a);
        }
        return this.c;
    }
}
