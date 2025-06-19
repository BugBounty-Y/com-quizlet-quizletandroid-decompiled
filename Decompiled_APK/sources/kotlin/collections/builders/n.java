package kotlin.collections.builders;

import androidx.compose.animation.d0;
import java.io.Externalizable;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Map;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class n implements Externalizable {

    @NotNull
    public static final m b = new m(null);
    public Object a;

    public n(Map map) {
        Intrinsics.checkNotNullParameter(map, "map");
        this.a = map;
    }

    private final Object readResolve() {
        return this.a;
    }

    @Override // java.io.Externalizable
    public final void readExternal(ObjectInput input) throws IOException {
        Intrinsics.checkNotNullParameter(input, "input");
        byte b2 = input.readByte();
        if (b2 != 0) {
            throw new InvalidObjectException(android.support.v4.media.session.a.f(b2, "Unsupported flags value: "));
        }
        int i = input.readInt();
        if (i < 0) {
            throw new InvalidObjectException(d0.m('.', i, "Illegal size value: "));
        }
        h builder = new h(i);
        for (int i2 = 0; i2 < i; i2++) {
            builder.put(input.readObject(), input.readObject());
        }
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a = builder.b();
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.Map] */
    @Override // java.io.Externalizable
    public final void writeExternal(ObjectOutput output) throws IOException {
        Intrinsics.checkNotNullParameter(output, "output");
        output.writeByte(0);
        output.writeInt(this.a.size());
        for (Map.Entry entry : this.a.entrySet()) {
            output.writeObject(entry.getKey());
            output.writeObject(entry.getValue());
        }
    }

    public n() {
        this(V.c());
    }
}
