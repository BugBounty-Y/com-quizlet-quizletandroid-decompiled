package com.google.mlkit.vision.documentscanner.internal;

import android.os.IBinder;
import android.os.IInterface;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.internal.AbstractC1656f;
import com.google.android.gms.internal.mlkit_vision_document_scanner.u7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.v7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.w7;
import com.google.mlkit.common.sdkinternal.h;

/* loaded from: classes2.dex */
public final class e extends AbstractC1656f {
    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 17895000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        int i = v7.b;
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.mlkit.vision.docscan.ui.aidls.IDocumentScannerService");
        return iInterfaceQueryLocalInterface instanceof w7 ? (w7) iInterfaceQueryLocalInterface : new u7(iBinder);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Feature[] h() {
        return new Feature[]{h.c};
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.mlkit.vision.docscan.ui.aidls.IDocumentScannerService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.mlkit.docscan.ui.DocumentScanningChimeraService.START";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final boolean p() {
        return true;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final boolean s() {
        return true;
    }
}
