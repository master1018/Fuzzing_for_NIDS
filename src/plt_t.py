option_pie = {
        "legend": {},
        "tooltip": {
            "trigger": 'axis',
            "showContent": "false"
        },
        "dataset": {
            "source": [
                ['', '2023'],
                ['正常规则', 1],
                ['签名重叠规则', 2],
                ['签名重复规则', 3],
                ['算法复杂度规则', 4],
                ['签名混淆规则', 4]
            ]
        },
        "series": [
            {
                "type": 'pie',
                "id": 'pie',
                "radius": ['40%', '75%'],
                #"center": ['50%', '30%'],
                "emphasis": {"focus": 'data',
                            "fontSize": '20',
                            "fontWeight": 'bold'},
                "label": {
                    "formatter": '{b}: {@2023} ({d}%)'
                },
            }
        ],
            "tooltip": {
                    "show": "true",
                },
            "label": {
                "show":"true"
    },
    }

option_bar = {
        "toolbox": {
        "show": "true",
        "feature": {
          "dataZoom": {
            "yAxisIndex": "none"
          },
          "dataView": {
            "readOnly": "false"
          },
          "magicType": {
            "type": ["line", "bar"]
          },
          "restore": {"show":"true"},
        }
      },
        "xAxis": {
            "type": 'category',
            "data": ['20 ~ 40%', '40 ~ 70%', '70 ~ 100%']
        },
        "yAxis": {
            "type": 'value'
        },
        "series": [{
            "data": [
                {"value":1, "itemStyle":{"color":"#00FF00"}},
                {"value":2, "itemStyle":{"color":"#FFFF00"}},
                {"value":3, "itemStyle":{"color":"#FF7D00"}},
                {"value":4, "itemStyle":{"color":"#FF0000"}}, 
                ],
            "type": 'bar'

        }],
        "tooltip": {
                        "show": "true"
                    },
        "label": {
            "show":"true"
        },
        
                        
        }
