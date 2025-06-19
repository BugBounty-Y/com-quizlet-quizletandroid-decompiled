package com.google.mlkit.vision.documentscanner;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
abstract class zza extends GmsDocumentScanningResult {
    public final ArrayList a;
    public final GmsDocumentScanningResult.Pdf b;

    public zza(ArrayList arrayList, GmsDocumentScanningResult.Pdf pdf) {
        this.a = arrayList;
        this.b = pdf;
    }

    @Override // com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult
    public final List a() {
        return this.a;
    }

    @Override // com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult
    public final GmsDocumentScanningResult.Pdf b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof GmsDocumentScanningResult)) {
            return false;
        }
        GmsDocumentScanningResult gmsDocumentScanningResult = (GmsDocumentScanningResult) obj;
        ArrayList arrayList = this.a;
        if (arrayList == null) {
            if (((zza) gmsDocumentScanningResult).a != null) {
                return false;
            }
        } else if (!arrayList.equals(((zza) gmsDocumentScanningResult).a)) {
            return false;
        }
        GmsDocumentScanningResult.Pdf pdf = this.b;
        return pdf == null ? ((zza) gmsDocumentScanningResult).b == null : pdf.equals(((zza) gmsDocumentScanningResult).b);
    }

    public final int hashCode() {
        ArrayList arrayList = this.a;
        int iHashCode = arrayList == null ? 0 : arrayList.hashCode();
        GmsDocumentScanningResult.Pdf pdf = this.b;
        return (pdf != null ? pdf.hashCode() : 0) ^ ((iHashCode ^ 1000003) * 1000003);
    }

    public final String toString() {
        return AbstractC0147y.e("GmsDocumentScanningResult{pages=", String.valueOf(this.a), ", pdf=", String.valueOf(this.b), "}");
    }
}
