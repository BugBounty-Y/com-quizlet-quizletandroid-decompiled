package androidx.room;

import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class u implements androidx.sqlite.db.g, androidx.sqlite.db.f {
    public static final TreeMap i = new TreeMap();
    public final int a;
    public volatile String b;
    public final long[] c;
    public final double[] d;
    public final String[] e;
    public final byte[][] f;
    public final int[] g;
    public int h;

    public u(int i2) {
        this.a = i2;
        int i3 = i2 + 1;
        this.g = new int[i3];
        this.c = new long[i3];
        this.d = new double[i3];
        this.e = new String[i3];
        this.f = new byte[i3][];
    }

    public static final u a(int i2, String query) {
        Intrinsics.checkNotNullParameter(query, "query");
        TreeMap treeMap = i;
        synchronized (treeMap) {
            Map.Entry entryCeilingEntry = treeMap.ceilingEntry(Integer.valueOf(i2));
            if (entryCeilingEntry == null) {
                Unit unit = Unit.a;
                u uVar = new u(i2);
                Intrinsics.checkNotNullParameter(query, "query");
                uVar.b = query;
                uVar.h = i2;
                return uVar;
            }
            treeMap.remove(entryCeilingEntry.getKey());
            u sqliteQuery = (u) entryCeilingEntry.getValue();
            sqliteQuery.getClass();
            Intrinsics.checkNotNullParameter(query, "query");
            sqliteQuery.b = query;
            sqliteQuery.h = i2;
            Intrinsics.checkNotNullExpressionValue(sqliteQuery, "sqliteQuery");
            return sqliteQuery;
        }
    }

    @Override // androidx.sqlite.db.f
    public final void E(int i2, byte[] value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.g[i2] = 5;
        this.f[i2] = value;
    }

    @Override // androidx.sqlite.db.f
    public final void R(int i2) {
        this.g[i2] = 1;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
    }

    @Override // androidx.sqlite.db.g
    public final String d() {
        String str = this.b;
        if (str != null) {
            return str;
        }
        throw new IllegalStateException("Required value was null.");
    }

    @Override // androidx.sqlite.db.g
    public final void f(androidx.sqlite.db.f statement) {
        Intrinsics.checkNotNullParameter(statement, "statement");
        int i2 = this.h;
        if (1 > i2) {
            return;
        }
        int i3 = 1;
        while (true) {
            int i4 = this.g[i3];
            if (i4 == 1) {
                statement.R(i3);
            } else if (i4 == 2) {
                statement.z(i3, this.c[i3]);
            } else if (i4 == 3) {
                statement.s(i3, this.d[i3]);
            } else if (i4 == 4) {
                String str = this.e[i3];
                if (str == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                statement.g(i3, str);
            } else if (i4 == 5) {
                byte[] bArr = this.f[i3];
                if (bArr == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                statement.E(i3, bArr);
            }
            if (i3 == i2) {
                return;
            } else {
                i3++;
            }
        }
    }

    @Override // androidx.sqlite.db.f
    public final void g(int i2, String value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.g[i2] = 4;
        this.e[i2] = value;
    }

    public final void i() {
        TreeMap treeMap = i;
        synchronized (treeMap) {
            treeMap.put(Integer.valueOf(this.a), this);
            if (treeMap.size() > 15) {
                int size = treeMap.size() - 10;
                Iterator it2 = treeMap.descendingKeySet().iterator();
                Intrinsics.checkNotNullExpressionValue(it2, "queryPool.descendingKeySet().iterator()");
                while (true) {
                    int i2 = size - 1;
                    if (size <= 0) {
                        break;
                    }
                    it2.next();
                    it2.remove();
                    size = i2;
                }
            }
            Unit unit = Unit.a;
        }
    }

    @Override // androidx.sqlite.db.f
    public final void s(int i2, double d) {
        this.g[i2] = 3;
        this.d[i2] = d;
    }

    @Override // androidx.sqlite.db.f
    public final void z(int i2, long j) {
        this.g[i2] = 2;
        this.c[i2] = j;
    }
}
