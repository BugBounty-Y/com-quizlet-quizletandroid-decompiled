package androidx.navigation.compose;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.net.Uri;
import androidx.navigation.C1291m;
import com.braze.Braze;
import com.braze.images.DefaultBrazeImageLoader;
import com.braze.managers.C1495h;
import com.braze.managers.C1496i;
import com.braze.managers.o0;
import com.braze.managers.s0;
import com.braze.push.BrazePushReceiver;
import com.braze.support.BrazeImageUtils;
import com.braze.support.IntentUtils;
import com.braze.support.WebContentUtils;
import com.comscore.streaming.EventType;
import java.io.File;
import java.net.URL;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4950i;
import org.json.JSONArray;
import org.json.JSONObject;

/* renamed from: androidx.navigation.compose.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1277j implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C1277j(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                ((s) this.b).f((C1291m) this.c, false);
                return Unit.a;
            case 1:
                return kotlin.collections.A.b(new Pair((coil3.fetch.f) this.b, (C4950i) this.c));
            case 2:
                return Braze._init_$lambda$27((Braze) this.b, (Context) this.c);
            case 3:
                return com.braze.communication.dust.h.a((kotlin.jvm.internal.J) this.b, (kotlin.jvm.internal.J) this.c);
            case 4:
                return com.braze.events.b.a((Class) this.b, (Set) this.c);
            case 5:
                return DefaultBrazeImageLoader.shouldSkipCaching$lambda$7$lambda$6((Map.Entry) this.b, (Uri) this.c);
            case 6:
                return DefaultBrazeImageLoader.getBitmapFromCache$lambda$13$lambda$12((String) this.b, (DefaultBrazeImageLoader) this.c);
            case 7:
                return C1495h.a((C1495h) this.b, (List) this.c);
            case 8:
                return C1496i.a((C1496i) this.b, (String) this.c);
            case 9:
                return s0.a((com.braze.events.internal.t) this.b, (o0) this.c);
            case 10:
                return com.braze.managers.y.a((String) this.b, (com.braze.managers.y) this.c);
            case 11:
                return com.braze.models.g.a(this.b, (JSONArray) this.c);
            case 12:
                return com.braze.models.outgoing.event.a.b((String) this.b, (com.braze.enums.h) this.c);
            case 13:
                return com.braze.models.outgoing.event.a.b((String) this.b, (String[]) this.c);
            case 14:
                return BrazePushReceiver.Companion.handlePush$lambda$3((String) this.b, (Intent) this.c);
            case 15:
                return com.braze.requests.d.a((com.braze.requests.d) this.b, (JSONObject) this.c);
            case 16:
                return com.braze.requests.d.a((com.braze.requests.d) this.b, (JSONArray) this.c);
            case 17:
                return com.braze.requests.d.a((com.braze.requests.d) this.b, (com.braze.models.response.m) this.c);
            case 18:
                return com.braze.requests.framework.queue.c.a((com.braze.requests.f) this.b, (com.braze.requests.framework.h) this.c);
            case 19:
                return com.braze.storage.p.a((kotlin.jvm.internal.J) this.b, (com.braze.storage.p) this.c);
            case 20:
                return com.braze.storage.p.a((LinkedHashSet) this.b, (Set) this.c);
            case 21:
                return com.braze.storage.v.a((com.braze.storage.v) this.b, (com.braze.models.i) this.c);
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.storage.v.a((com.braze.storage.v) this.b, (Set) this.c);
            case EventType.AUDIO /* 23 */:
                return BrazeImageUtils.getLocalBitmap$lambda$13((Uri) this.b, (BitmapFactory.Options) this.c);
            case EventType.VIDEO /* 24 */:
                return BrazeImageUtils.getRemoteBitmap$lambda$20((URL) this.b, (BitmapFactory.Options) this.c);
            case EventType.SUBS /* 25 */:
                return BrazeImageUtils.getRemoteBitmap$lambda$21((String) this.b, (Exception) this.c);
            case EventType.CDN /* 26 */:
                return IntentUtils.addComponentAndSendBroadcast$lambda$2$lambda$1((ComponentName) this.b, (Intent) this.c);
            case 27:
                return WebContentUtils.unpackZipIntoDirectory$lambda$11((File) this.b, (String) this.c);
            case 28:
                return com.braze.support.delegates.a.a(this.b, (kotlin.reflect.n) this.c);
            default:
                return com.braze.triggers.actions.g.a((com.braze.triggers.actions.g) this.b, (com.braze.triggers.events.b) this.c);
        }
    }
}
