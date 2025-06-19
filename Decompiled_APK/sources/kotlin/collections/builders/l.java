package kotlin.collections.builders;

import androidx.compose.animation.d0;
import java.io.Externalizable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Collection;
import java.util.Iterator;
import kotlin.collections.A;
import kotlin.collections.K;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class l implements Externalizable {

    @NotNull
    public static final k c = new k(null);
    public Object a;
    public final int b;

    public l() {
        this(0, K.a);
    }

    private final Object readResolve() {
        return this.a;
    }

    @Override // java.io.Externalizable
    public final void readExternal(ObjectInput input) throws IOException {
        Object objA;
        Intrinsics.checkNotNullParameter(input, "input");
        byte b = input.readByte();
        int i = b & 1;
        if ((b & (-2)) != 0) {
            throw new InvalidObjectException(d0.m('.', b, "Unsupported flags value: "));
        }
        int i2 = input.readInt();
        if (i2 < 0) {
            throw new InvalidObjectException(d0.m('.', i2, "Illegal size value: "));
        }
        int i3 = 0;
        if (i == 0) {
            d dVar = new d(i2);
            while (i3 < i2) {
                dVar.add(input.readObject());
                i3++;
            }
            objA = A.a(dVar);
        } else {
            if (i != 1) {
                throw new InvalidObjectException(d0.m('.', i, "Unsupported collection type tag: "));
            }
            p pVar = new p(new h(i2));
            while (i3 < i2) {
                pVar.add(input.readObject());
                i3++;
            }
            objA = Z.a(pVar);
        }
        this.a = objA;
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.Collection] */
    @Override // java.io.Externalizable
    public final void writeExternal(ObjectOutput output) throws IOException {
        Intrinsics.checkNotNullParameter(output, "output");
        output.writeByte(this.b);
        output.writeInt(this.a.size());
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            output.writeObject(it2.next());
        }
    }

    public l(int i, Collection collection) {
        Intrinsics.checkNotNullParameter(collection, "collection");
        this.a = collection;
        this.b = i;
    }
}
