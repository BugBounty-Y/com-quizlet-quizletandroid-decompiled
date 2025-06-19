package com.skydoves.balloon.compose;

import android.content.pm.PackageManager;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import androidx.compose.ui.platform.ComposeView;
import com.google.firebase.messaging.s;
import com.snowplowanalytics.core.tracker.q;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.DispatchException;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:102:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x031a  */
    /* JADX WARN: Type inference failed for: r15v0 */
    /* JADX WARN: Type inference failed for: r15v1, types: [java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r15v2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void a() throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 1446
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.skydoves.balloon.compose.a.a():void");
    }

    @Override // java.lang.Runnable
    public final void run() throws PackageManager.NameNotFoundException, IOException, DispatchException {
        long size;
        switch (this.a) {
            case 0:
                ((Function1) this.b).invoke((ComposeView) this.c);
                return;
            case 1:
                com.snowplowanalytics.core.emitter.a this$0 = (com.snowplowanalytics.core.emitter.a) this.b;
                com.snowplowanalytics.snowplow.payload.b payload = (com.snowplowanalytics.snowplow.payload.b) this.c;
                Intrinsics.checkNotNullParameter(this$0, "this$0");
                Intrinsics.checkNotNullParameter(payload, "$payload");
                androidx.work.impl.background.greedy.d dVar = this$0.m;
                dVar.getClass();
                Intrinsics.checkNotNullParameter(payload, "payload");
                if (dVar.b()) {
                    dVar.h();
                    dVar.g(payload);
                } else {
                    synchronized (dVar) {
                        ((ArrayList) dVar.b).add(payload);
                    }
                }
                androidx.work.impl.background.greedy.d dVar2 = this$0.m;
                if (dVar2.b()) {
                    dVar2.h();
                    size = DatabaseUtils.queryNumEntries((SQLiteDatabase) dVar2.c, "events");
                } else {
                    size = ((ArrayList) dVar2.b).size();
                }
                if (size < this$0.u.a || !this$0.c.compareAndSet(false, true)) {
                    return;
                }
                try {
                    this$0.c();
                    this$0.a((com.snowplowanalytics.snowplow.network.d) this$0.y.get());
                    return;
                } catch (Throwable th) {
                    this$0.c.set(false);
                    String TAG = this$0.a;
                    Intrinsics.checkNotNullExpressionValue(TAG, "TAG");
                    com.snowplowanalytics.core.tracker.e.b(TAG, "Received error during emission process: %s", th);
                    return;
                }
            case 2:
                Runnable runnable = (Runnable) this.b;
                if (runnable != null) {
                    try {
                        runnable.run();
                        return;
                    } catch (Throwable th2) {
                        s sVar = (s) this.c;
                        if (sVar != null) {
                            sVar.a(th2);
                            return;
                        }
                        return;
                    }
                }
                return;
            case 3:
                androidx.core.util.a onSessionUpdate = (androidx.core.util.a) this.b;
                Intrinsics.checkNotNullParameter(onSessionUpdate, "$onSessionUpdate");
                com.google.firebase.crashlytics.internal.settings.d state = (com.google.firebase.crashlytics.internal.settings.d) this.c;
                Intrinsics.checkNotNullParameter(state, "$state");
                onSessionUpdate.accept(state);
                return;
            case 4:
                LinkedList stateMachines = (LinkedList) this.b;
                Intrinsics.checkNotNullParameter(stateMachines, "$stateMachines");
                q event = (q) this.c;
                Intrinsics.checkNotNullParameter(event, "$event");
                Iterator it2 = stateMachines.iterator();
                while (it2.hasNext()) {
                    ((com.snowplowanalytics.core.statemachine.f) it2.next()).b(event);
                }
                return;
            case 5:
                a();
                return;
            case 6:
                ((C5028l) this.b).E((kotlinx.coroutines.android.d) this.c, Unit.a);
                return;
            default:
                ((kotlinx.coroutines.selects.e) ((kotlinx.coroutines.selects.f) this.b)).g((kotlinx.coroutines.selects.b) this.c, Unit.a);
                return;
        }
    }
}
