package com.google.mlkit.vision.documentscanner;

import android.net.Uri;
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult;

/* loaded from: classes2.dex */
abstract class zzb extends GmsDocumentScanningResult.Page {
    public final Uri a;

    public zzb(Uri uri) {
        if (uri == null) {
            throw new NullPointerException("Null imageUri");
        }
        this.a = uri;
    }

    @Override // com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult.Page
    public final Uri a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof GmsDocumentScanningResult.Page)) {
            return false;
        }
        return this.a.equals(((zzb) ((GmsDocumentScanningResult.Page) obj)).a);
    }

    public final int hashCode() {
        return this.a.hashCode() ^ 1000003;
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("Page{imageUri=", this.a.toString(), "}");
    }
}
