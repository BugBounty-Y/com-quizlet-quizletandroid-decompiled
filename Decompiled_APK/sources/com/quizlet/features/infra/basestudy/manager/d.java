package com.quizlet.features.infra.basestudy.manager;

import androidx.collection.C0208f;
import com.quizlet.eventlogger.features.study.StudyFunnelEventLogger;
import com.quizlet.generated.enums.EnumC4519s1;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements com.quizlet.infra.contracts.studyfunnel.a {
    public final StudyFunnelEventLogger a;
    public final C0208f b;
    public final C0208f c;
    public final C0208f d;
    public final C0208f e;
    public final C0208f f;
    public final C0208f g;
    public final C0208f h;
    public final C0208f i;

    public d(StudyFunnelEventLogger studyFunnelEventLogger) {
        Intrinsics.checkNotNullParameter(studyFunnelEventLogger, "studyFunnelEventLogger");
        this.a = studyFunnelEventLogger;
        this.b = new C0208f(0);
        this.c = new C0208f(0);
        this.d = new C0208f(0);
        this.e = new C0208f(0);
        this.f = new C0208f(0);
        this.g = new C0208f(0);
        this.h = new C0208f(0);
        this.i = new C0208f(0);
    }

    public final void a() {
        this.b.clear();
        this.c.clear();
        this.d.clear();
        this.e.clear();
        this.f.clear();
        this.g.clear();
        this.h.clear();
        this.i.clear();
    }

    public final C0208f b(int i) {
        if (i == 1) {
            return this.b;
        }
        if (i == 20) {
            return this.f;
        }
        if (i == 29) {
            return this.h;
        }
        if (i == 3) {
            return this.c;
        }
        if (i == 4) {
            return this.d;
        }
        switch (i) {
            case 13:
                return this.e;
            case 14:
            case 15:
            case 16:
                return this.g;
            default:
                timber.log.c.a.d(i + " not recognized by StudyFunnelEventManager", new Object[0]);
                return null;
        }
    }

    public final c c(long j) {
        b bVar;
        UUID uuid = (UUID) this.b.get(String.valueOf(j));
        if (uuid == null || (bVar = (b) this.i.get(uuid)) == null) {
            return null;
        }
        return new c(uuid, bVar);
    }

    public final void d(int i, String modelId) {
        UUID uuid;
        Intrinsics.checkNotNullParameter(modelId, "modelId");
        if (i == 1) {
            uuid = (UUID) this.b.get(modelId);
            if (uuid == null) {
                return;
            }
        } else if (i == 20) {
            uuid = (UUID) this.f.get(modelId);
            if (uuid == null) {
                return;
            }
        } else if (i == 29) {
            uuid = (UUID) this.h.get(modelId);
            if (uuid == null) {
                return;
            }
        } else if (i == 3) {
            uuid = (UUID) this.c.get(modelId);
            if (uuid == null) {
                return;
            }
        } else if (i != 4) {
            switch (i) {
                case 13:
                    uuid = (UUID) this.e.get(modelId);
                    if (uuid == null) {
                        return;
                    }
                    break;
                case 14:
                case 15:
                case 16:
                    uuid = (UUID) this.g.get(modelId);
                    if (uuid == null) {
                        return;
                    }
                    break;
                default:
                    throw new IllegalStateException(i + " not recognized by StudyFunnelEventManager");
            }
        } else {
            uuid = (UUID) this.d.get(modelId);
            if (uuid == null) {
                return;
            }
        }
        UUID uuid2 = uuid;
        b bVar = (b) this.i.get(uuid2);
        if (bVar == null) {
            throw new IllegalStateException("expected a mapping for funnel ID: " + uuid2 + " in funnelIdToPayloadMap");
        }
        StudyFunnelEventLogger.a(this.a, EnumC4519s1.CLICK, bVar.b, bVar.c, uuid2, bVar.d, bVar.e, bVar.f, bVar.g, null, bVar.h, bVar.i, null, 2304);
    }
}
