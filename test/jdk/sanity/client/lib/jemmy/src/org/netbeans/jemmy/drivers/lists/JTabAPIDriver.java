/*
 * Copyright (c) 1997, 2016, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package org.netbeans.jemmy.drivers.lists;

import org.netbeans.jemmy.QueueTool;
import org.netbeans.jemmy.drivers.LightSupportiveDriver;
import org.netbeans.jemmy.drivers.ListDriver;
import org.netbeans.jemmy.operators.ComponentOperator;
import org.netbeans.jemmy.operators.JTabbedPaneOperator;

/**
 * List driver for javax.swing.JTabbedPane component type.
 *
 * @author Alexandre Iline(alexandre.iline@oracle.com)
 */
public class JTabAPIDriver extends LightSupportiveDriver implements ListDriver {

    private QueueTool queueTool;

    /**
     * Constructs a JTabMouseDriver.
     */
    public JTabAPIDriver() {
        super(new String[]{"org.netbeans.jemmy.operators.JTabbedPaneOperator"});
        queueTool = new QueueTool();
    }

    @Override
    public void selectItem(final ComponentOperator oper, final int index) {
        if (index != -1) {
            queueTool.invokeSmoothly(new QueueTool.QueueAction<Void>("Selecting tab " + index + " by setting selectedIndex") {
                @Override
                public Void launch() {
                    ((JTabbedPaneOperator) oper).setSelectedIndex(index);
                    return null;
                }
            });
        }
    }
}
