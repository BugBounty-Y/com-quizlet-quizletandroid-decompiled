package io.ktor.client.plugins;

import java.util.List;

/* renamed from: io.ktor.client.plugins.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4861h extends io.ktor.http.content.c {
    public final /* synthetic */ int a = 1;
    public final Long b;
    public final io.ktor.http.d c;
    public final /* synthetic */ Object d;

    public C4861h(io.ktor.client.request.c cVar, io.ktor.http.d dVar, Object obj) {
        this.d = obj;
        io.ktor.http.l lVar = cVar.c;
        List list = io.ktor.http.n.a;
        String strQ = lVar.q("Content-Length");
        this.b = strQ != null ? Long.valueOf(Long.parseLong(strQ)) : null;
        if (dVar == null) {
            io.ktor.http.d dVar2 = io.ktor.http.b.a;
            dVar = io.ktor.http.b.a;
        }
        this.c = dVar;
    }

    @Override // io.ktor.http.content.c
    public final Long a() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // io.ktor.http.content.c
    public final io.ktor.http.d b() {
        switch (this.a) {
        }
        return this.c;
    }

    public C4861h(io.ktor.util.pipeline.e eVar, io.ktor.http.d dVar, Object obj) {
        this.d = obj;
        io.ktor.http.l lVar = ((io.ktor.client.request.c) eVar.a).c;
        List list = io.ktor.http.n.a;
        String strQ = lVar.q("Content-Length");
        this.b = strQ != null ? Long.valueOf(Long.parseLong(strQ)) : null;
        if (dVar == null) {
            io.ktor.http.d dVar2 = io.ktor.http.b.a;
            dVar = io.ktor.http.b.a;
        }
        this.c = dVar;
    }
}
