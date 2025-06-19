package androidx.compose.foundation.text.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.text.selection.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0520a extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0533n b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0520a(InterfaceC0533n interfaceC0533n, int i) {
        super(0);
        this.a = i;
        this.b = interfaceC0533n;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
        }
        return Boolean.valueOf(Q4.h(this.b.a()));
    }
}
