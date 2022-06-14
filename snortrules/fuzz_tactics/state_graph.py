#! /usr/bin/env python
# -*- coding: UTF-8 -*-

from queue import Queue
#from snort_rules import *
import snort_rules

'''
Construct a state graph for imb flowbits
'''


class Node:
    def __init__(self, ntype, bits, key, ruleId = 0):
        self.ntype = ntype
        self.bits = bits
        self.id = key
        self.ruleId = ruleId
        self.sons = {}
        self.fathers = {}

    def addSon(self, son):
        if son.id not in self.sons.keys() and son.id != self.id:
            self.sons[son.id] = son

    def addFather(self, father):
        if father.id not in self.fathers.keys() and father.id != self.id:
            self.fathers[father.id] = father

    def delSon(self, son):
        if self.sons.has_key(son.id):
            del self.sons[son.id]


class State_graph:
    def __init__(self, snortRules):
        # 在这里构建图
        # 每个规则有自己的一个flowbits
        # 去遍历规则集
        # 对于每一个规则，解析其中的flowbits
        # 对于flowbits，如果第一个是set，则添加到根节点
        # 如果是check，就去找到那个分支，添加在后面
        # 如果是unset，去找到那个分支，然后放在最后面
        self.rootnode = Node("", "", 0)
        self.nodeList = {self.rootnode.id: self.rootnode}
        num = 1
        for snortRule in snortRules:
            print("第", num, "个节点")
            if num == 36:
                print("这是个关键的节点")
            snorRuleAttr = snort_rules.SnortRuleAttr(snortRule)
            flowbits = snorRuleAttr.get_opt_flowbits()
            ruleId = '-'.join([str(snorRuleAttr.get_opt_gid()), str(snorRuleAttr.get_opt_sid())])
            # flowbits 中的flowbits都在一个分支上
            fatherNode = self.rootnode
            # 对于每一个规则的flowbits
            for flowbit in flowbits:
                # 如果是set操作
                if flowbit['command'] == 'set' and len(flowbit) > 1:
                    setNode = Node('set', flowbit['bits'], num, ruleId)
                    self.addNode(fatherNode, setNode)
                    fatherNode = setNode
                    num += 1

                # 如果是check的isset或者isnotset
                if flowbit['command'] == 'isset' or flowbit['command'] == 'isnotset':
                    checkNode = Node(flowbit.get('command'), flowbit.get('bits'), num, ruleId)
                    for rootSon in self.rootnode.sons.values():
                        # 找到对应的那个分支，
                        if rootSon.bits == flowbit.get('bits'):
                            # 把check节点放到这个分支的最后面
                            q = []
                            q.append(rootSon)
                            while len(q) > 0:
                                checkTmpNode = q.pop(0)
                                if len(checkTmpNode.sons) == 0:
                                    self.addNode(checkTmpNode, checkNode)
                                    fatherNode = checkNode
                                    num += 1
                                else:
                                    for checkTmpNodeSon in checkTmpNode.sons.values():
                                        q.append(checkTmpNodeSon)

                #如果是unset，如果是一样的规则则放在isset的后面
                if flowbit['command'] == 'unset':
                    # 如果不是单独的，就加入前置节点后面,一般不会单个
                    setNode = Node('unset', flowbit['bits'], num, ruleId)
                    self.addNode(fatherNode, setNode)

    # 以一个列表的形式获取一个分支
    def getBranch(self, bits):
        # 返回一个分支的列表
        for node in self.rootnode.sons.values():
            #找到对应分支
            if node.bits == bits:
                return self.getNodeSons(node)

    # 获取一个节点的所有后置节点
    def getNodeSons(self, node):
        nodeList = []
        nodeList.append(node)
        if len(node.sons) > 0:
            for nodeSon in node.sons.values():
                nodeList.append(self.getNodeSons(nodeSon))
        return nodeList

    # 获取一个节点的所有前置节点
    def getNodeFathers(self, node):
        nodeList = []
        if len(node.fathers) > 0:
            for nodeFather in node.fathers.values():
                nodeList.append(self.getNodeFathers(nodeFather))
        nodeList.append(node)
        return nodeList

    # 获取一个分支的ruleId的列表
    def getRuleIdList(self, bits):
        # 对于相同bits的节点，把它的前向后向节点额ruleId都添加进去
        ruleIdList = []
        bitsNode = Node("", "", -1)
        for node in self.nodeList:
            if node.bits == bits:
                bitsNode = node
        bitsRootFatherNode = self.findNodeRootFather(bitsNode)
        tmpNode = bitsRootFatherNode
        ruleIdList.append(tmpNode.ruleId)
        while len(tmpNode.sons) > 0:
            tmpNode = tmpNode.sons.values()[0]
            if tmpNode.ruleId != ruleIdList[-1]:
                ruleIdList.append(tmpNode.ruleId)
        return ruleIdList


    # 递归获取节点的RuleId
    def getRuleId(self, node):
        ruleIdList = []
        ruleIdList.append(node.ruleId)
        tmpNode = node
        while len(tmpNode.sons) > 0:
            for tmpNodeSon in tmpNode.sons.values():
                ruleIdList.append(self.getRuleId(tmpNodeSon))
        return ruleIdList

    def findNodeRootFather(self,node):
        tmpNode = node
        rootFatherNode = node
        while tmpNode != self.rootnode:
            tmpNode = rootFatherNode.father.values[0]
            rootFatherNode = rootFatherNode.father.values[0]
        return rootFatherNode


    def addNode(self, fatherNode, node):
        self.nodeList[fatherNode.id].addSon(node)
        node.addFather(fatherNode)
        if not node.id in self.nodeList.keys():
            self.nodeList[node.id] = node
        #if len(node.sons) == 0:
            #return
        #else:
            #for sonNode in node.sons.values():
                #self.addNode(node, sonNode)

    def delNodeByKey(self, nodeKey):
        if len(self.nodeList[nodeKey].sons) == 0:
            del self.nodeList[nodeKey]
        else:
            for key in self.nodeList[nodeKey].sons.keys():
                self.delNodeByKey(key)

    def printGraph(self, root, spaceStr=""):
        print(spaceStr + root.ntype + ": " + root.bits)
        if len(root.sons.keys()) == 0:
            return
        else:
            spaceStr += " " 
            for node in root.sons.values():
                self.printGraph(node, spaceStr)

    def printStateGraph(self):
        self.printGraph(self.rootnode)


print("终于进入激动人心的测试环节：")
ruleFile = snort_rules.RuleFile("/home/haoyu/stateful_smb.rules")
state_graph = State_graph(ruleFile.get_rule_set())
state_graph.printStateGraph()
print("运行结束")
