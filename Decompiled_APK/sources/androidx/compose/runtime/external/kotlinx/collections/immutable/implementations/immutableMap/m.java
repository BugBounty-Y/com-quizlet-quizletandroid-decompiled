package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.ui.graphics.vector.G;
import androidx.core.view.C;
import java.util.Iterator;
import java.util.regex.Matcher;
import kotlin.collections.AbstractC4911b;
import kotlin.collections.AbstractC4919j;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.MatchGroup;

/* loaded from: classes.dex */
public final class m extends AbstractC4911b {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ m(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        switch (this.a) {
            case 0:
                return ((c) this.b).d();
            case 1:
                return ((AbstractC4919j) this.b).d();
            case 2:
                return ((kotlin.text.m) this.b).a.groupCount() + 1;
            case 3:
                return ((kotlinx.collections.immutable.implementations.immutableMap.c) this.b).d();
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.c) this.b).d();
        }
    }

    public MatchGroup b(int i) {
        kotlin.text.m mVar = (kotlin.text.m) this.b;
        Matcher matcher = mVar.a;
        IntRange intRangeH = kotlin.ranges.l.h(matcher.start(i), matcher.end(i));
        if (intRangeH.a < 0) {
            return null;
        }
        String strGroup = mVar.a.group(i);
        Intrinsics.checkNotNullExpressionValue(strGroup, "group(...)");
        return new MatchGroup(strGroup, intRangeH);
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        switch (this.a) {
            case 0:
                return ((c) this.b).containsValue(obj);
            case 1:
                return ((AbstractC4919j) this.b).containsValue(obj);
            case 2:
                if (obj == null ? true : obj instanceof MatchGroup) {
                    return super.contains((MatchGroup) obj);
                }
                return false;
            case 3:
                return ((kotlinx.collections.immutable.implementations.immutableMap.c) this.b).containsValue(obj);
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.c) this.b).containsValue(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection
    public boolean isEmpty() {
        switch (this.a) {
            case 2:
                return false;
            default:
                return super.isEmpty();
        }
    }

    @Override // java.util.Collection, java.lang.Iterable
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                n nVar = ((c) this.b).b;
                o[] oVarArr = new o[8];
                for (int i = 0; i < 8; i++) {
                    oVarArr[i] = new p(2);
                }
                return new l(nVar, oVarArr);
            case 1:
                return new G(((AbstractC4919j) this.b).a().iterator(), 2);
            case 2:
                return new C(kotlin.sequences.q.h(CollectionsKt.D(B.h(this)), new kotlin.text.l(this)));
            case 3:
                kotlinx.collections.immutable.implementations.immutableMap.j node = ((kotlinx.collections.immutable.implementations.immutableMap.c) this.b).b;
                Intrinsics.checkNotNullParameter(node, "node");
                o[] oVarArr2 = new o[8];
                for (int i2 = 0; i2 < 8; i2++) {
                    oVarArr2[i2] = new kotlinx.collections.immutable.implementations.immutableMap.k(2);
                }
                return new kotlinx.collections.immutable.implementations.immutableMap.i(node, oVarArr2);
            default:
                return new kotlinx.collections.immutable.implementations.persistentOrderedMap.h((kotlinx.collections.immutable.implementations.persistentOrderedMap.c) this.b, 2);
        }
    }

    public m(kotlinx.collections.immutable.implementations.immutableMap.c map) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(map, "map");
        this.b = map;
    }

    public m(kotlinx.collections.immutable.implementations.persistentOrderedMap.c map) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(map, "map");
        this.b = map;
    }
}
