package androidx.compose.foundation.layout;

/* loaded from: classes.dex */
public final class Z extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ int[] b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Z(int[] iArr, int i) {
        super(3);
        this.a = i;
        this.b = iArr;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                int iIntValue = ((Number) obj2).intValue();
                ((Number) obj3).intValue();
                return Integer.valueOf(this.b[iIntValue]);
            default:
                int iIntValue2 = ((Number) obj2).intValue();
                ((Number) obj3).intValue();
                return Integer.valueOf(this.b[iIntValue2]);
        }
    }
}
