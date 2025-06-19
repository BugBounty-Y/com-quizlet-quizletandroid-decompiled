package com.quizlet.ui.compose.modifiers;

import android.view.View;
import androidx.compose.ui.graphics.I;
import androidx.compose.ui.graphics.drawscope.d;
import androidx.compose.ui.node.G;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.skydoves.balloon.internals.DefinitionKt;
import io.ktor.client.engine.okhttp.f;
import io.ktor.client.plugins.AbstractC4875w;
import io.ktor.client.plugins.H;
import io.ktor.client.plugins.InterfaceC4874v;
import io.ktor.http.AbstractC4879a;
import io.ktor.util.e;
import io.ktor.utils.io.k;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.N;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.C5036u;
import kotlinx.coroutines.E;
import kotlinx.coroutines.Q;
import kotlinx.coroutines.y0;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.descriptors.h;
import kotlinx.serialization.internal.Z;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.internal.n;
import okhttp3.J;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        SerialDescriptor descriptor;
        switch (this.a) {
            case 0:
                G drawWithContent = (G) obj;
                Intrinsics.checkNotNullParameter(drawWithContent, "$this$drawWithContent");
                drawWithContent.b();
                d.J(drawWithContent, (I) this.b, 0L, 0L, DefinitionKt.NO_Float_VALUE, null, 62);
                break;
            case 1:
                View it2 = (View) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ((com.quizlet.uicommon.ui.common.text.c) this.b).b.invoke();
                break;
            case 2:
                io.ktor.client.c scope = (io.ktor.client.c) obj;
                Intrinsics.checkNotNullParameter(scope, "scope");
                e eVar = (e) scope.i.a(AbstractC4875w.a, new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(28));
                LinkedHashMap linkedHashMap = scope.k.b;
                InterfaceC4874v interfaceC4874v = (InterfaceC4874v) this.b;
                Object obj2 = linkedHashMap.get(interfaceC4874v.getKey());
                Intrinsics.d(obj2);
                Object objB = interfaceC4874v.b((Function1) obj2);
                interfaceC4874v.a(objB, scope);
                eVar.e(interfaceC4874v.getKey(), objB);
                break;
            case 3:
                ((f) this.b).close();
                break;
            case 4:
                J j = (J) this.b;
                if (j != null) {
                    j.close();
                }
                break;
            case 5:
                Throwable th = (Throwable) obj;
                org.slf4j.b bVar = H.a;
                A0 a0 = (A0) this.b;
                if (th != null) {
                    bVar.n("Cancelling request because engine Job failed with error: " + th);
                    E.j(a0, "Engine failed", th);
                } else {
                    bVar.n("Cancelling request because engine Job completed");
                    a0.k0();
                }
                break;
            case 6:
                ((Q) this.b).dispose();
                break;
            case 7:
                Throwable th2 = (Throwable) obj;
                A0 a02 = ((io.ktor.client.request.c) this.b).e;
                Intrinsics.e(a02, "null cannot be cast to non-null type kotlinx.coroutines.CompletableJob");
                if (th2 == null) {
                    a02.k0();
                } else {
                    a02.U(new C5036u(th2, false));
                }
                break;
            case 8:
                ((y0) this.b).j(null);
                break;
            case 9:
                Byte b = (Byte) obj;
                byte bByteValue = b.byteValue();
                StringBuilder sb = (StringBuilder) this.b;
                if (bByteValue == 32) {
                    sb.append("%20");
                } else if (AbstractC4879a.a.contains(b) || AbstractC4879a.c.contains(b)) {
                    sb.append((char) bByteValue);
                } else {
                    sb.append(AbstractC4879a.g(bByteValue));
                }
                break;
            case 10:
                Throwable th3 = (Throwable) obj;
                if (th3 != null) {
                    k kVar = (k) this.b;
                    if (!kVar.j()) {
                        kVar.b(th3);
                    }
                }
                break;
            case 11:
                ((com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a) this.b).invoke();
                break;
            case 12:
                break;
            case 13:
                ((io.reactivex.rxjava3.disposables.b) this.b).dispose();
                break;
            case 14:
                kotlinx.serialization.descriptors.a buildSerialDescriptor = (kotlinx.serialization.descriptors.a) obj;
                Intrinsics.checkNotNullParameter(buildSerialDescriptor, "$this$buildSerialDescriptor");
                KSerializer kSerializer = ((kotlinx.serialization.a) this.b).b;
                List annotations = (kSerializer == null || (descriptor = kSerializer.getDescriptor()) == null) ? null : descriptor.getAnnotations();
                if (annotations == null) {
                    annotations = K.a;
                }
                buildSerialDescriptor.getClass();
                Intrinsics.checkNotNullParameter(annotations, "<set-?>");
                buildSerialDescriptor.b = annotations;
                break;
            case 15:
                kotlinx.serialization.descriptors.a buildSerialDescriptor2 = (kotlinx.serialization.descriptors.a) obj;
                Intrinsics.checkNotNullParameter(buildSerialDescriptor2, "$this$buildSerialDescriptor");
                R1.g(N.a);
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor2, DBUserFields.Names.USER_UPGRADE_TYPE, q0.b);
                StringBuilder sb2 = new StringBuilder("kotlinx.serialization.Polymorphic<");
                kotlinx.serialization.c cVar = (kotlinx.serialization.c) this.b;
                sb2.append(((C4950i) cVar.a).f());
                sb2.append('>');
                kotlinx.serialization.descriptors.a.a(buildSerialDescriptor2, "value", T1.g(sb2.toString(), h.b, new SerialDescriptor[0], new com.sdk.growthbook.utils.a(24)));
                List list = cVar.b;
                Intrinsics.checkNotNullParameter(list, "<set-?>");
                buildSerialDescriptor2.b = list;
                break;
            case 16:
                kotlinx.serialization.descriptors.a buildSerialDescriptor3 = (kotlinx.serialization.descriptors.a) obj;
                Intrinsics.checkNotNullParameter(buildSerialDescriptor3, "$this$buildSerialDescriptor");
                List list2 = ((Z) this.b).b;
                buildSerialDescriptor3.getClass();
                Intrinsics.checkNotNullParameter(list2, "<set-?>");
                buildSerialDescriptor3.b = list2;
                break;
            case 17:
                int iIntValue = ((Integer) obj).intValue();
                StringBuilder sb3 = new StringBuilder();
                SerialDescriptor serialDescriptor = (SerialDescriptor) this.b;
                sb3.append(serialDescriptor.g(iIntValue));
                sb3.append(": ");
                sb3.append(serialDescriptor.i(iIntValue).a());
                break;
            case 18:
                kotlinx.serialization.descriptors.a buildClassSerialDescriptor = (kotlinx.serialization.descriptors.a) obj;
                Intrinsics.checkNotNullParameter(buildClassSerialDescriptor, "$this$buildClassSerialDescriptor");
                kotlinx.serialization.a aVar = (kotlinx.serialization.a) this.b;
                kotlinx.serialization.descriptors.a.a(buildClassSerialDescriptor, "first", aVar.b.getDescriptor());
                kotlinx.serialization.descriptors.a.a(buildClassSerialDescriptor, "second", ((KSerializer) aVar.c).getDescriptor());
                kotlinx.serialization.descriptors.a.a(buildClassSerialDescriptor, "third", ((KSerializer) aVar.d).getDescriptor());
                break;
            default:
                kotlinx.serialization.json.k node = (kotlinx.serialization.json.k) obj;
                Intrinsics.checkNotNullParameter(node, "node");
                n nVar = (n) this.b;
                nVar.M((String) CollectionsKt.U(nVar.a), node);
                break;
        }
        return Unit.a;
    }
}
