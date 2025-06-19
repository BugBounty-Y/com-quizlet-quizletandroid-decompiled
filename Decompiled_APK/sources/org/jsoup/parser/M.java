package org.jsoup.parser;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public abstract class M extends androidx.sqlite.db.b {
    public String c;
    public String d;
    public final StringBuilder e;
    public String f;
    public boolean g;
    public final StringBuilder h;
    public String i;
    public boolean j;
    public boolean k;
    public boolean l;
    public org.jsoup.nodes.b m;

    public M() {
        super(4);
        this.e = new StringBuilder();
        this.g = false;
        this.h = new StringBuilder();
        this.j = false;
        this.k = false;
        this.l = false;
    }

    public final String A() {
        String str = this.c;
        if (str == null || str.length() == 0) {
            throw new ValidationException("Must be false");
        }
        return this.c;
    }

    public final void B(String str) {
        this.c = str;
        this.d = AbstractC3386r2.c(str.trim());
    }

    public final void C() {
        if (this.m == null) {
            this.m = new org.jsoup.nodes.b();
        }
        boolean z = this.g;
        StringBuilder sb = this.h;
        StringBuilder sb2 = this.e;
        if (z && this.m.a < 512) {
            String strTrim = (sb2.length() > 0 ? sb2.toString() : this.f).trim();
            if (strTrim.length() > 0) {
                this.m.c(strTrim, this.j ? sb.length() > 0 ? sb.toString() : this.i : this.k ? "" : null);
            }
        }
        androidx.sqlite.db.b.r(sb2);
        this.f = null;
        this.g = false;
        androidx.sqlite.db.b.r(sb);
        this.i = null;
        this.j = false;
        this.k = false;
    }

    @Override // androidx.sqlite.db.b
    /* renamed from: D, reason: merged with bridge method [inline-methods] */
    public M q() {
        this.c = null;
        this.d = null;
        androidx.sqlite.db.b.r(this.e);
        this.f = null;
        this.g = false;
        androidx.sqlite.db.b.r(this.h);
        this.i = null;
        this.k = false;
        this.j = false;
        this.l = false;
        this.m = null;
        return this;
    }

    public final void v(char c) {
        this.j = true;
        String str = this.i;
        StringBuilder sb = this.h;
        if (str != null) {
            sb.append(str);
            this.i = null;
        }
        sb.append(c);
    }

    public final void w(String str) {
        this.j = true;
        String str2 = this.i;
        StringBuilder sb = this.h;
        if (str2 != null) {
            sb.append(str2);
            this.i = null;
        }
        if (sb.length() == 0) {
            this.i = str;
        } else {
            sb.append(str);
        }
    }

    public final void x(int[] iArr) {
        this.j = true;
        String str = this.i;
        StringBuilder sb = this.h;
        if (str != null) {
            sb.append(str);
            this.i = null;
        }
        for (int i : iArr) {
            sb.appendCodePoint(i);
        }
    }

    public final void y(String str) {
        String strReplace = str.replace((char) 0, (char) 65533);
        String str2 = this.c;
        if (str2 != null) {
            strReplace = str2.concat(strReplace);
        }
        this.c = strReplace;
        this.d = AbstractC3386r2.c(strReplace.trim());
    }

    public final boolean z() {
        return this.m != null;
    }
}
