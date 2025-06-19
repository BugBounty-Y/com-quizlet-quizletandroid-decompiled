package com.quizlet.explanations.feedback.data;

import com.google.android.gms.internal.mlkit_vision_document_scanner.X6;

/* loaded from: classes2.dex */
public final class d extends X6 {
    public static final d b = new d(0);
    public static final d c = new d(1);
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.X6
    public final String b() {
        switch (this.a) {
            case 0:
                return "The solution is not displaying correctly on my device";
            default:
                return "The solution is incorrect";
        }
    }
}
