package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class f0 {
    public final SharedPreferences a;

    public f0(Context context, String str, String str2) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = assistantMode.refactored.a.g(0, context, "com.appboy.storage.appboy_event_storage", str, str2);
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Deleting event from storage with uid ", str);
    }

    public static final String c(com.braze.models.i iVar) {
        return "Adding event to storage with uid " + ((com.braze.models.outgoing.event.b) iVar).d;
    }

    public final Collection b() {
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        Map<String, ?> all = this.a.getAll();
        Intrinsics.checkNotNullExpressionValue(all, "getAll(...)");
        for (Map.Entry<String, ?> entry : all.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            J j = new J();
            j.a = "";
            try {
                Intrinsics.e(value, "null cannot be cast to non-null type kotlin.String");
                j.a = (String) value;
                Intrinsics.d(key);
                com.braze.models.i iVarE = com.braze.models.outgoing.event.b.g.e((String) value, key);
                if (iVarE != null) {
                    linkedHashSet.add(iVarE);
                }
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new C(j, key, 0), 4, (Object) null);
                SharedPreferences.Editor editorEdit = this.a.edit();
                editorEdit.remove(key);
                editorEdit.apply();
                Unit unit = Unit.a;
            }
        }
        return linkedHashSet;
    }

    public static final String a(J j, String str) {
        return androidx.compose.ui.node.B.j(new StringBuilder("Could not create BrazeEvent from [serialized event string="), (String) j.a, ", unique identifier=", str, "] ... Deleting!");
    }

    public final void a(com.braze.models.i event) {
        Intrinsics.checkNotNullParameter(event, "event");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.n(event, 8), 7, (Object) null);
        SharedPreferences.Editor editorEdit = this.a.edit();
        String str = ((com.braze.models.outgoing.event.b) event).d;
        event.getClass();
        String string = ((com.braze.models.outgoing.event.b) event).forJsonPut().toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        editorEdit.putString(str, string).apply();
    }

    public final void a(Set events) {
        Intrinsics.checkNotNullParameter(events, "events");
        SharedPreferences.Editor editorEdit = this.a.edit();
        Iterator it2 = events.iterator();
        while (it2.hasNext()) {
            String str = ((com.braze.models.outgoing.event.b) ((com.braze.models.i) it2.next())).d;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.managers.C(str, 29), 7, (Object) null);
            editorEdit.remove(str);
        }
        editorEdit.apply();
    }
}
