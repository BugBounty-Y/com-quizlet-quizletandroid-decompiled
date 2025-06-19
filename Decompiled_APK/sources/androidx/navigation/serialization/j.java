package androidx.navigation.serialization;

import androidx.compose.foundation.text.z0;
import androidx.navigation.AbstractC1285g;
import androidx.navigation.S;
import com.quizlet.explanations.myexplanations.data.p;
import com.quizlet.explanations.myexplanations.data.q;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.notes.detail.MagicNotesDetailActivity;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ j(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        Object obj4 = this.b;
        Object obj5 = this.c;
        switch (this.a) {
            case 0:
                int iIntValue = ((Integer) obj).intValue();
                String name = (String) obj2;
                S type = (S) obj3;
                Intrinsics.checkNotNullParameter(name, "argName");
                Intrinsics.checkNotNullParameter(type, "navType");
                Object obj6 = ((Map) obj4).get(name);
                Intrinsics.d(obj6);
                List value = (List) obj6;
                com.quizlet.data.repository.progress.b bVar = (com.quizlet.data.repository.progress.b) obj5;
                Intrinsics.checkNotNullParameter(name, "name");
                Intrinsics.checkNotNullParameter(type, "type");
                Intrinsics.checkNotNullParameter(value, "value");
                int iOrdinal = (((type instanceof AbstractC1285g) || ((KSerializer) bVar.a).getDescriptor().j(iIntValue)) ? f.b : f.a).ordinal();
                if (iOrdinal != 0) {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    Iterator it2 = value.iterator();
                    while (it2.hasNext()) {
                        bVar.a(name, (String) it2.next());
                    }
                } else {
                    if (value.size() != 1) {
                        StringBuilder sbY = android.support.v4.media.session.a.y("Expected one value for argument ", name, ", found ");
                        sbY.append(value.size());
                        sbY.append("values instead.");
                        throw new IllegalArgumentException(sbY.toString().toString());
                    }
                    bVar.c = ((String) bVar.c) + '/' + ((String) CollectionsKt.L(value));
                }
                return Unit.a;
            case 1:
                ((Integer) obj3).getClass();
                Intrinsics.checkNotNullParameter((String) obj, "<unused var>");
                Intrinsics.checkNotNullParameter((String) obj2, "<unused var>");
                ((z0) obj4).invoke((p) obj5);
                return Unit.a;
            case 2:
                ((Long) obj).getClass();
                ((Integer) obj3).getClass();
                Intrinsics.checkNotNullParameter((String) obj2, "<unused var>");
                ((z0) obj4).invoke((q) obj5);
                return Unit.a;
            case 3:
                String noteUuid = (String) obj;
                Intrinsics.checkNotNullParameter(noteUuid, "uuid");
                com.quizlet.quizletandroid.ui.navigationmanagers.e eVar = (com.quizlet.quizletandroid.ui.navigationmanagers.e) ((com.quizlet.features.notes.manager.a) obj4);
                eVar.getClass();
                Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
                int i = MagicNotesDetailActivity.i;
                eVar.b(assistantMode.utils.studiableMetadata.b.J(eVar.a, noteUuid, ((Boolean) obj2).booleanValue(), (AddMaterialFolderData) obj3));
                ((Function0) obj5).invoke();
                return Unit.a;
            default:
                AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = kotlinx.coroutines.sync.c.h;
                ((kotlinx.coroutines.sync.b) obj5).getClass();
                kotlinx.coroutines.sync.c cVar = (kotlinx.coroutines.sync.c) obj4;
                atomicReferenceFieldUpdater.set(cVar, null);
                cVar.f(null);
                return Unit.a;
        }
    }
}
