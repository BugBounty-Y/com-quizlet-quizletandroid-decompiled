package com.quizlet.features.notes.upload.composables.upload;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.q;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.google.android.gms.internal.mlkit_vision_common.U3;
import com.quizlet.data.model.m2;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ m2 b;
    public final /* synthetic */ q c;
    public final /* synthetic */ int d;

    public /* synthetic */ a(int i, m2 m2Var, q qVar, int i2) {
        this.a = 2;
        this.d = i;
        this.b = m2Var;
        this.c = qVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Integer) obj2).getClass();
        switch (i) {
            case 0:
                AbstractC3332e.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            case 1:
                AbstractC3336f.a(this.b, this.c, interfaceC0806l, C0776c.H(this.d | 1));
                break;
            default:
                int iH = C0776c.H(1);
                U3.a(this.d, this.b, this.c, interfaceC0806l, iH);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(m2 m2Var, q qVar, int i, int i2) {
        this.a = i2;
        this.b = m2Var;
        this.c = qVar;
        this.d = i;
    }
}
