package kotlinx.serialization;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.descriptors.h;
import kotlinx.serialization.internal.q0;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ e b;

    public /* synthetic */ d(e eVar, int i) {
        this.a = i;
        this.b = eVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        kotlinx.serialization.descriptors.a buildSerialDescriptor = (kotlinx.serialization.descriptors.a) obj;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(buildSerialDescriptor, "$this$buildSerialDescriptor");
                R1.g(N.a);
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, DBUserFields.Names.USER_UPGRADE_TYPE, q0.b);
                StringBuilder sb = new StringBuilder("kotlinx.serialization.Sealed<");
                e eVar = this.b;
                sb.append(eVar.a.f());
                sb.append('>');
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, "value", T1.g(sb.toString(), h.b, new SerialDescriptor[0], new d(eVar, 1)));
                List list = eVar.b;
                Intrinsics.checkNotNullParameter(list, "<set-?>");
                buildSerialDescriptor.b = list;
                break;
            default:
                Intrinsics.checkNotNullParameter(buildSerialDescriptor, "$this$buildSerialDescriptor");
                for (Map.Entry entry : this.b.e.entrySet()) {
                    kotlinx.serialization.descriptors.a.a(buildSerialDescriptor, (String) entry.getKey(), ((KSerializer) entry.getValue()).getDescriptor());
                }
                break;
        }
        return Unit.a;
    }
}
