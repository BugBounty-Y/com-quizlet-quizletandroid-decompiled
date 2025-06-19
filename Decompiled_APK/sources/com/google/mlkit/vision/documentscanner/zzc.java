package com.google.mlkit.vision.documentscanner;

import android.net.Uri;
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult;

/* loaded from: classes2.dex */
abstract class zzc extends GmsDocumentScanningResult.Pdf {
    public final Uri a;
    public final int b;

    public zzc(Uri uri, int i) {
        if (uri == null) {
            throw new NullPointerException("Null uri");
        }
        this.a = uri;
        this.b = i;
    }

    @Override // com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult.Pdf
    public final int a() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof GmsDocumentScanningResult.Pdf) {
            GmsDocumentScanningResult.Pdf pdf = (GmsDocumentScanningResult.Pdf) obj;
            if (this.a.equals(((zzc) pdf).a) && this.b == ((zzc) pdf).b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b;
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(android.support.v4.media.session.a.y("Pdf{uri=", this.a.toString(), ", pageCount="), this.b, "}");
    }
}
