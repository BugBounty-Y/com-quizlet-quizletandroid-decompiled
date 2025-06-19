package androidx.core.view;

import android.content.ClipData;
import android.net.Uri;
import android.os.Bundle;
import android.view.ContentInfo;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;

/* renamed from: androidx.core.view.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1046f implements InterfaceC1044e, InterfaceC1048g {
    public final /* synthetic */ int a = 0;
    public ClipData b;
    public int c;
    public int d;
    public Uri e;
    public Bundle f;

    public /* synthetic */ C1046f() {
    }

    @Override // androidx.core.view.InterfaceC1044e
    public C1050h build() {
        return new C1050h(new C1046f(this));
    }

    @Override // androidx.core.view.InterfaceC1048g
    public ClipData f() {
        return this.b;
    }

    @Override // androidx.core.view.InterfaceC1044e
    public void j(Bundle bundle) {
        this.f = bundle;
    }

    @Override // androidx.core.view.InterfaceC1044e
    public void n(Uri uri) {
        this.e = uri;
    }

    @Override // androidx.core.view.InterfaceC1048g
    public int o() {
        return this.d;
    }

    @Override // androidx.core.view.InterfaceC1048g
    public ContentInfo p() {
        return null;
    }

    @Override // androidx.core.view.InterfaceC1044e
    public void r(int i) {
        this.d = i;
    }

    public String toString() {
        String str;
        switch (this.a) {
            case 1:
                StringBuilder sb = new StringBuilder("ContentInfoCompat{clip=");
                sb.append(this.b.getDescription());
                sb.append(", source=");
                int i = this.c;
                sb.append(i != 0 ? i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? String.valueOf(i) : "SOURCE_PROCESS_TEXT" : "SOURCE_AUTOFILL" : "SOURCE_DRAG_AND_DROP" : "SOURCE_INPUT_METHOD" : "SOURCE_CLIPBOARD" : "SOURCE_APP");
                sb.append(", flags=");
                int i2 = this.d;
                sb.append((i2 & 1) != 0 ? "FLAG_CONVERT_TO_PLAIN_TEXT" : String.valueOf(i2));
                Uri uri = this.e;
                if (uri == null) {
                    str = "";
                } else {
                    str = ", hasLinkUri(" + uri.toString().length() + ")";
                }
                sb.append(str);
                return android.support.v4.media.session.a.t(sb, this.f != null ? ", hasExtras" : "", "}");
            default:
                return super.toString();
        }
    }

    @Override // androidx.core.view.InterfaceC1048g
    public int v() {
        return this.c;
    }

    public C1046f(C1046f c1046f) {
        ClipData clipData = c1046f.b;
        clipData.getClass();
        this.b = clipData;
        int i = c1046f.c;
        AbstractC3242q6.e(i, 0, "source", 5);
        this.c = i;
        int i2 = c1046f.d;
        if ((i2 & 1) == i2) {
            this.d = i2;
            this.e = c1046f.e;
            this.f = c1046f.f;
        } else {
            throw new IllegalArgumentException("Requested flags 0x" + Integer.toHexString(i2) + ", but only 0x" + Integer.toHexString(1) + " are allowed");
        }
    }
}
