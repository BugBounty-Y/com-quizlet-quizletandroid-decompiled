package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

/* loaded from: classes.dex */
public final class p extends o {
    public final /* synthetic */ int e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ p(int i) {
        super(0);
        this.e = i;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.e) {
            case 0:
                int i = this.d;
                this.d = i + 2;
                Object[] objArr = this.b;
                return new a(0, objArr[i], objArr[i + 1]);
            case 1:
                int i2 = this.d;
                this.d = i2 + 2;
                return this.b[i2];
            default:
                int i3 = this.d;
                this.d = i3 + 2;
                return this.b[i3 + 1];
        }
    }
}
