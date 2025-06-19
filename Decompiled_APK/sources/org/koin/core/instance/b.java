package org.koin.core.instance;

import com.quizlet.data.repository.set.f;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.koin.core.error.InstanceCreationException;

/* loaded from: classes3.dex */
public abstract class b {
    public final org.koin.core.definition.b a;

    public b(org.koin.core.definition.b beanDefinition) {
        Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
        this.a = beanDefinition;
    }

    public Object a(f context) throws InstanceCreationException {
        Intrinsics.checkNotNullParameter(context, "context");
        StringBuilder sb = new StringBuilder("| (+) '");
        org.koin.core.definition.b bVar = this.a;
        sb.append(bVar);
        sb.append('\'');
        String string = sb.toString();
        j jVar = (j) context.b;
        jVar.a(string);
        try {
            org.koin.core.parameter.a aVar = (org.koin.core.parameter.a) context.d;
            if (aVar == null) {
                aVar = new org.koin.core.parameter.a();
            }
            return bVar.d.invoke((org.koin.core.scope.a) context.c, aVar);
        } catch (Exception parent) {
            Intrinsics.checkNotNullParameter(parent, "e");
            StringBuilder sb2 = new StringBuilder();
            sb2.append(parent);
            sb2.append("\n\t");
            StackTraceElement[] stackTrace = parent.getStackTrace();
            Intrinsics.checkNotNullExpressionValue(stackTrace, "getStackTrace(...)");
            ArrayList arrayList = new ArrayList();
            for (StackTraceElement stackTraceElement : stackTrace) {
                String className = stackTraceElement.getClassName();
                Intrinsics.checkNotNullExpressionValue(className, "getClassName(...)");
                if (StringsKt.G(className, "sun.reflect", false)) {
                    break;
                }
                arrayList.add(stackTraceElement);
            }
            sb2.append(CollectionsKt.S(arrayList, "\n\t", null, null, null, 62));
            String msg = "* Instance creation error : could not create instance for '" + bVar + "': " + sb2.toString();
            jVar.getClass();
            Intrinsics.checkNotNullParameter(msg, "msg");
            jVar.g(org.koin.core.logger.a.d, msg);
            String msg2 = "Could not create instance for '" + bVar + '\'';
            Intrinsics.checkNotNullParameter(msg2, "msg");
            Intrinsics.checkNotNullParameter(parent, "parent");
            throw new InstanceCreationException(msg2, parent);
        }
    }

    public abstract Object b(f fVar);

    public final boolean equals(Object obj) {
        b bVar = obj instanceof b ? (b) obj : null;
        return Intrinsics.b(this.a, bVar != null ? bVar.a : null);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
