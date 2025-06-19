package kotlinx.serialization.json;

import androidx.camera.camera2.internal.p0;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4927s;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.encoding.Decoder;

/* loaded from: classes3.dex */
public abstract class c {
    public static final b d = new b(new i(false, false, false, false, true, "    ", DBUserFields.Names.USER_UPGRADE_TYPE, false, true, a.b), kotlinx.serialization.modules.f.a);
    public final i a;
    public final p0 b;
    public final com.quizlet.quizletandroid.ui.login.h c = new com.quizlet.quizletandroid.ui.login.h();

    public c(i iVar, p0 p0Var) {
        this.a = iVar;
        this.b = p0Var;
    }

    public final Object a(KSerializer deserializer, k element) {
        Decoder mVar;
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        Intrinsics.checkNotNullParameter(element, "element");
        Intrinsics.checkNotNullParameter(this, "json");
        Intrinsics.checkNotNullParameter(element, "element");
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        String str = null;
        if (element instanceof v) {
            mVar = new kotlinx.serialization.json.internal.o(this, (v) element, str, 12);
        } else if (element instanceof d) {
            mVar = new kotlinx.serialization.json.internal.p(this, (d) element);
        } else {
            if (!(element instanceof r) && !element.equals(JsonNull.INSTANCE)) {
                throw new NoWhenBranchMatchedException();
            }
            mVar = new kotlinx.serialization.json.internal.m(this, (y) element, null);
        }
        return mVar.u(deserializer);
    }

    public final Object b(String string, KSerializer deserializer) {
        Intrinsics.checkNotNullParameter(deserializer, "deserializer");
        Intrinsics.checkNotNullParameter(string, "string");
        androidx.camera.camera2.internal.concurrent.a aVarE = kotlinx.serialization.json.internal.k.e(this, string);
        Object objU = new kotlinx.serialization.json.internal.u(this, kotlinx.serialization.json.internal.y.c, aVarE, deserializer.getDescriptor(), null).u(deserializer);
        if (aVarE.h() == 10) {
            return objU;
        }
        androidx.camera.camera2.internal.concurrent.a.r(aVarE, "Expected EOF after parsing, but had " + ((String) aVarE.f).charAt(aVarE.b - 1) + " instead", 0, null, 6);
        throw null;
    }

    public final String c(KSerializer serializer, Object obj) {
        char[] cArr;
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(22, (char) 0);
        kotlinx.serialization.json.internal.d dVar = kotlinx.serialization.json.internal.d.c;
        synchronized (dVar) {
            C4927s c4927s = (C4927s) dVar.b;
            cArr = null;
            char[] cArr2 = (char[]) (c4927s.isEmpty() ? null : c4927s.removeLast());
            if (cArr2 != null) {
                dVar.a -= cArr2.length;
                cArr = cArr2;
            }
        }
        if (cArr == null) {
            cArr = new char[128];
        }
        sVar.c = cArr;
        try {
            kotlinx.serialization.json.internal.k.k(this, sVar, serializer, obj);
            return sVar.toString();
        } finally {
            sVar.l();
        }
    }
}
