package androidx.compose.ui.platform;

import android.database.ContentObserver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Handler;
import com.google.android.gms.internal.measurement.C3068v1;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class o1 extends ContentObserver {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o1(Object obj, int i) {
        super(null);
        this.a = i;
        this.b = obj;
    }

    @Override // android.database.ContentObserver
    public boolean deliverSelfNotifications() {
        switch (this.a) {
            case 1:
                return true;
            default:
                return super.deliverSelfNotifications();
        }
    }

    @Override // android.database.ContentObserver
    public void onChange(boolean z) {
        Cursor cursor;
        switch (this.a) {
            case 1:
                androidx.appcompat.widget.j1 j1Var = (androidx.appcompat.widget.j1) this.b;
                if (!j1Var.b || (cursor = j1Var.c) == null || cursor.isClosed()) {
                    return;
                }
                j1Var.a = j1Var.c.requery();
                return;
            case 2:
                ((AtomicBoolean) ((com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) this.b).a).set(true);
                return;
            case 3:
                C3068v1 c3068v1 = (C3068v1) this.b;
                synchronized (c3068v1.e) {
                    c3068v1.f = null;
                    c3068v1.c.run();
                }
                synchronized (c3068v1) {
                    try {
                        Iterator it2 = c3068v1.g.iterator();
                        if (it2.hasNext()) {
                            if (it2.next() != null) {
                                throw new ClassCastException();
                            }
                            throw null;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return;
            default:
                super.onChange(z);
                return;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o1(kotlinx.coroutines.channels.h hVar, Handler handler) {
        super(handler);
        this.a = 0;
        this.b = hVar;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o1(androidx.appcompat.widget.j1 j1Var) {
        super(new Handler());
        this.a = 1;
        this.b = j1Var;
    }

    @Override // android.database.ContentObserver
    public void onChange(boolean z, Uri uri) {
        switch (this.a) {
            case 0:
                ((kotlinx.coroutines.channels.h) this.b).o(Unit.a);
                break;
            default:
                super.onChange(z, uri);
                break;
        }
    }
}
