package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class d implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public int b;
    public boolean c;
    public final Object[] d;

    public d(n nVar, o[] oVarArr) {
        this.a = 0;
        this.d = oVarArr;
        this.c = true;
        oVarArr[0].a(Integer.bitCount(nVar.a) * 2, 0, nVar.d);
        this.b = 0;
        a();
    }

    public void a() {
        int i = this.b;
        o[] oVarArr = (o[]) this.d;
        o oVar = oVarArr[i];
        if (oVar.d < oVar.c) {
            return;
        }
        while (-1 < i) {
            int iD = d(i);
            if (iD == -1) {
                o oVar2 = oVarArr[i];
                int i2 = oVar2.d;
                Object[] objArr = oVar2.b;
                if (i2 < objArr.length) {
                    int length = objArr.length;
                    oVar2.d = i2 + 1;
                    iD = d(i);
                }
            }
            if (iD != -1) {
                this.b = iD;
                return;
            }
            if (i > 0) {
                o oVar3 = oVarArr[i - 1];
                int i3 = oVar3.d;
                int length2 = oVar3.b.length;
                oVar3.d = i3 + 1;
            }
            oVarArr[i].a(0, 0, n.e.d);
            i--;
        }
        this.c = false;
    }

    public void b() {
        int i = this.b;
        o[] oVarArr = (o[]) this.d;
        o oVar = oVarArr[i];
        if (oVar.d < oVar.c) {
            return;
        }
        while (-1 < i) {
            int iE = e(i);
            if (iE == -1) {
                o oVar2 = oVarArr[i];
                int i2 = oVar2.d;
                Object[] objArr = oVar2.b;
                if (i2 < objArr.length) {
                    int length = objArr.length;
                    oVar2.d = i2 + 1;
                    iE = e(i);
                }
            }
            if (iE != -1) {
                this.b = iE;
                return;
            }
            if (i > 0) {
                o oVar3 = oVarArr[i - 1];
                int i3 = oVar3.d;
                int length2 = oVar3.b.length;
                oVar3.d = i3 + 1;
            }
            o oVar4 = oVarArr[i];
            Object[] buffer = kotlinx.collections.immutable.implementations.immutableMap.j.e.d;
            oVar4.getClass();
            Intrinsics.checkNotNullParameter(buffer, "buffer");
            Intrinsics.checkNotNullParameter(buffer, "buffer");
            oVar4.b = buffer;
            oVar4.c = 0;
            oVar4.d = 0;
            i--;
        }
        this.c = false;
    }

    public int d(int i) {
        o[] oVarArr = (o[]) this.d;
        o oVar = oVarArr[i];
        int i2 = oVar.d;
        if (i2 < oVar.c) {
            return i;
        }
        Object[] objArr = oVar.b;
        if (i2 >= objArr.length) {
            return -1;
        }
        int length = objArr.length;
        Object obj = objArr[i2];
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNodeBaseIterator, V of androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.TrieNodeBaseIterator>");
        n nVar = (n) obj;
        if (i == 6) {
            o oVar2 = oVarArr[i + 1];
            Object[] objArr2 = nVar.d;
            oVar2.a(objArr2.length, 0, objArr2);
        } else {
            oVarArr[i + 1].a(Integer.bitCount(nVar.a) * 2, 0, nVar.d);
        }
        return d(i + 1);
    }

    public int e(int i) {
        o[] oVarArr = (o[]) this.d;
        o oVar = oVarArr[i];
        int i2 = oVar.d;
        if (i2 < oVar.c) {
            return i;
        }
        Object[] objArr = oVar.b;
        if (i2 >= objArr.length) {
            return -1;
        }
        int length = objArr.length;
        Object obj = objArr[i2];
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.collections.immutable.implementations.immutableMap.TrieNode<K of kotlinx.collections.immutable.implementations.immutableMap.TrieNodeBaseIterator, V of kotlinx.collections.immutable.implementations.immutableMap.TrieNodeBaseIterator>");
        kotlinx.collections.immutable.implementations.immutableMap.j jVar = (kotlinx.collections.immutable.implementations.immutableMap.j) obj;
        if (i == 6) {
            o oVar2 = oVarArr[i + 1];
            Object[] buffer = jVar.d;
            int length2 = buffer.length;
            oVar2.getClass();
            Intrinsics.checkNotNullParameter(buffer, "buffer");
            Intrinsics.checkNotNullParameter(buffer, "buffer");
            oVar2.b = buffer;
            oVar2.c = length2;
            oVar2.d = 0;
        } else {
            o oVar3 = oVarArr[i + 1];
            Object[] buffer2 = jVar.d;
            int iBitCount = Integer.bitCount(jVar.a) * 2;
            oVar3.getClass();
            Intrinsics.checkNotNullParameter(buffer2, "buffer");
            Intrinsics.checkNotNullParameter(buffer2, "buffer");
            oVar3.b = buffer2;
            oVar3.c = iBitCount;
            oVar3.d = 0;
        }
        return e(i + 1);
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
        }
        return this.c;
    }

    @Override // java.util.Iterator
    public Object next() {
        switch (this.a) {
            case 0:
                if (!this.c) {
                    throw new NoSuchElementException();
                }
                Object next = ((o[]) this.d)[this.b].next();
                a();
                return next;
            default:
                if (!this.c) {
                    throw new NoSuchElementException();
                }
                Object next2 = ((o[]) this.d)[this.b].next();
                b();
                return next2;
        }
    }

    @Override // java.util.Iterator
    public void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public d(kotlinx.collections.immutable.implementations.immutableMap.j node, o[] path) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(node, "node");
        Intrinsics.checkNotNullParameter(path, "path");
        this.d = path;
        this.c = true;
        o oVar = path[0];
        Object[] buffer = node.d;
        int iBitCount = Integer.bitCount(node.a) * 2;
        oVar.getClass();
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        Intrinsics.checkNotNullParameter(buffer, "buffer");
        oVar.b = buffer;
        oVar.c = iBitCount;
        oVar.d = 0;
        this.b = 0;
        b();
    }
}
