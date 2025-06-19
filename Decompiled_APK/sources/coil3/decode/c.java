package coil3.decode;

/* loaded from: classes.dex */
public final class c implements j {
    public final kotlinx.coroutines.sync.i a;
    public final n b;

    public c(kotlinx.coroutines.sync.i iVar, n nVar) {
        this.a = iVar;
        this.b = nVar;
    }

    @Override // coil3.decode.j
    public final k a(coil3.fetch.i iVar, coil3.request.m mVar) {
        return new e(iVar.a, mVar, this.a, this.b);
    }
}
