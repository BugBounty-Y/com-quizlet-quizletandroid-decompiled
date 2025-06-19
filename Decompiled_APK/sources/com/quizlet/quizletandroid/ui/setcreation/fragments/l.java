package com.quizlet.quizletandroid.ui.setcreation.fragments;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class l implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ ScanDocumentFragment b;

    public /* synthetic */ l(ScanDocumentFragment scanDocumentFragment, int i) {
        this.a = i;
        this.b = scanDocumentFragment;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.U();
                return Unit.a;
            case 1:
                this.b.U();
                return Unit.a;
            case 2:
                ScanDocumentFragment scanDocumentFragment = this.b;
                scanDocumentFragment.e0().f.a.z("ocr_enable_camera_permission");
                scanDocumentFragment.a0().F(scanDocumentFragment, false);
                return Unit.a;
            default:
                ScanDocumentFragment scanDocumentFragment2 = this.b;
                if (scanDocumentFragment2.l != null) {
                    androidx.camera.camera2.internal.compat.workaround.e.r(scanDocumentFragment2);
                    return Unit.a;
                }
                Intrinsics.m("permissionsManager");
                throw null;
        }
    }
}
