package assistantMode.refactored.modelTypes;

import androidx.compose.animation.d0;
import assistantMode.refactored.enums.j;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class Card implements d {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, null, null, null, new C5048d(CardSide$$serializer.INSTANCE, 0)};
    public final long a;
    public final long b;
    public final j c;
    public final long d;
    public final List e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Card$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Card(int i, long j, long j2, j jVar, long j3, List list) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, Card$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
        this.c = jVar;
        this.d = j3;
        this.e = list;
    }

    public final CardSide a(long j) {
        Object next;
        Iterator it2 = this.e.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            if (((CardSide) next).a == j) {
                break;
            }
        }
        return (CardSide) next;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Card)) {
            return false;
        }
        Card card = (Card) obj;
        return this.a == card.a && this.b == card.b && this.c == card.c && this.d == card.d && Intrinsics.b(this.e, card.e);
    }

    @Override // assistantMode.refactored.modelTypes.d
    public final long getId() {
        return this.a;
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.d((this.c.hashCode() + d0.d(Long.hashCode(this.a) * 31, 31, this.b)) * 31, 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Card(id=");
        sb.append(this.a);
        sb.append(", studiableContainerId=");
        sb.append(this.b);
        sb.append(", studiableContainerType=");
        sb.append(this.c);
        sb.append(", lastModified=");
        sb.append(this.d);
        sb.append(", cardSides=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }

    public Card(long j, long j2, long j3, ArrayList cardSides) {
        j studiableContainerType = j.b;
        Intrinsics.checkNotNullParameter(studiableContainerType, "studiableContainerType");
        Intrinsics.checkNotNullParameter(cardSides, "cardSides");
        this.a = j;
        this.b = j2;
        this.c = studiableContainerType;
        this.d = j3;
        this.e = cardSides;
    }
}
