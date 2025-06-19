package com.quizlet.quizletandroid.ui.library;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Y4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.Z4;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.library.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final /* synthetic */ class C4661f implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlinx.collections.immutable.e b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ boolean e;
    public final /* synthetic */ int f;

    public /* synthetic */ C4661f(kotlinx.collections.immutable.e eVar, Function1 function1, Function1 function12, boolean z, int i, int i2) {
        this.a = i2;
        this.b = eVar;
        this.c = function1;
        this.d = function12;
        this.e = z;
        this.f = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.f | 1);
                Function1 function1 = this.d;
                boolean z = this.e;
                Y4.c(this.b, this.c, function1, z, (InterfaceC0806l) obj, iH);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.f | 1);
                Function1 function12 = this.d;
                boolean z2 = this.e;
                Z4.a(this.b, this.c, function12, z2, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }
}
